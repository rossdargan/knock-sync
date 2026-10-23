#!/usr/bin/env python3
"""Sync the knock allowlist (Cloudflare Worker) + static entries into UniFi traffic matching lists.

Outbound only: polls the Worker, then updates UniFi via the Network Integration API.
Runs as a long-lived loop (designed for a container); one failed cycle never stops it.

  python3 knock_sync.py               # run forever (default)
  python3 knock_sync.py --once        # single sync, exit 0/1
  python3 knock_sync.py --dump        # print the current UniFi lists and exit (check item format)
  python3 knock_sync.py --healthcheck # exit 0 if a sync succeeded recently (Docker HEALTHCHECK)

API budget (defaults):
  * Worker: 1 GET every SYNC_INTERVAL (15s => 5,760/day, well under the 100k/day Workers free tier).
    Sends If-None-Match so a Worker that returns ETags can answer 304.
  * UniFi: GET+PUT only when the desired set changes, plus a drift check every RECONCILE_INTERVAL.
  * Failures back off exponentially (capped at MAX_BACKOFF) and honour Retry-After on 429/503.
"""
import argparse
import ipaddress
import json
import logging
import os
import random
import signal
import socket
import ssl
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field

log = logging.getLogger("knock-sync")

# UniFi may refuse an empty list, and an empty list must still mean "nobody":
# use documentation addresses as placeholders. Seed both lists with these in the UI.
SENTINEL = {4: "192.0.2.1", 6: "2001:db8::/64"}

KNOCK_VARS = ("KNOCK_URL", "KNOCK_SYNC_TOKEN", "CF_ACCESS_CLIENT_ID", "CF_ACCESS_CLIENT_SECRET")
UNIFI_VARS = ("UNIFI_HOST", "UNIFI_API_KEY", "UNIFI_SITE_ID", "UNIFI_LIST_V4_ID")


def _csv(value):
    return [v.strip() for v in (value or "").split(",") if v.strip()]


def _bool(value, default):
    if value is None or value == "":
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


@dataclass
class Config:
    unifi_host: str
    unifi_key: str
    site: str
    list_v4: str
    list_v6: str = ""
    knock_url: str = ""
    sync_token: str = ""
    cf_id: str = ""
    cf_secret: str = ""
    static_ips: list = field(default_factory=list)
    static_hosts: list = field(default_factory=list)
    static_file: str = "/config/static.txt"
    verify_tls: bool = False
    knock_doh: bool = True
    interval: float = 15.0
    reconcile_interval: float = 300.0
    static_refresh: float = 300.0
    max_backoff: float = 300.0
    health_file: str = "/tmp/knock-sync.health"
    health_max_age: float = 0.0

    @classmethod
    def from_env(cls, env=os.environ, need_knock=True):
        required = UNIFI_VARS + (KNOCK_VARS if need_knock else ())
        missing = [k for k in required if not env.get(k)]
        if missing:
            raise SystemExit(f"missing required environment variables: {', '.join(missing)}")
        interval = max(float(env.get("SYNC_INTERVAL", 15)), 5.0)
        return cls(
            unifi_host=env["UNIFI_HOST"].rstrip("/"),
            unifi_key=env["UNIFI_API_KEY"],
            site=env["UNIFI_SITE_ID"],
            list_v4=env["UNIFI_LIST_V4_ID"],
            list_v6=env.get("UNIFI_LIST_V6_ID", ""),
            knock_url=env.get("KNOCK_URL", "").rstrip("/"),
            sync_token=env.get("KNOCK_SYNC_TOKEN", ""),
            cf_id=env.get("CF_ACCESS_CLIENT_ID", ""),
            cf_secret=env.get("CF_ACCESS_CLIENT_SECRET", ""),
            static_ips=_csv(env.get("STATIC_IPS")),
            static_hosts=_csv(env.get("STATIC_HOSTS")),
            static_file=env.get("STATIC_FILE", "/config/static.txt"),
            verify_tls=_bool(env.get("UNIFI_VERIFY_TLS"), False),
            knock_doh=_bool(env.get("KNOCK_DOH"), True),
            interval=interval,
            reconcile_interval=float(env.get("RECONCILE_INTERVAL", 300)),
            static_refresh=float(env.get("STATIC_REFRESH", 300)),
            max_backoff=float(env.get("MAX_BACKOFF", 300)),
            health_file=env.get("HEALTH_FILE", "/tmp/knock-sync.health"),
            health_max_age=float(env.get("HEALTH_MAX_AGE", 0)) or max(120.0, interval * 4),
        )


class RetryLater(Exception):
    def __init__(self, message, retry_after):
        super().__init__(message)
        self.retry_after = retry_after


def _retry_after(err):
    try:
        return max(float(err.headers.get("Retry-After", "")), 1.0)
    except (TypeError, ValueError, AttributeError):
        return 60.0


def http_json(method, url, headers, body=None, context=None, timeout=15):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    if data:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=context) as r:
            raw = r.read()
            final_url, resp_headers = r.geturl(), r.headers
    except urllib.error.HTTPError as e:
        if e.code in (429, 503):
            raise RetryLater(f"{method} {url}: HTTP {e.code}", _retry_after(e)) from e
        raise
    try:
        return json.loads(raw or b"null"), resp_headers
    except json.JSONDecodeError as e:
        hint = " (redirected - Cloudflare Access probably rejected the service token)" if final_url != url else ""
        raise RuntimeError(f"{method} {url}: response was not JSON{hint}") from e


# --- DNS-over-HTTPS pinning for the knock host ------------------------------------------------
# Resolve the knock hostname via DoH so a local DNS override/intercept (e.g. a LAN record pointing
# *.dargan.uk at an internal proxy) can't hijack it. TLS still validates against the hostname.

class DohResolver:
    def __init__(self, host, min_ttl=60):
        self.host = host
        self.min_ttl = min_ttl
        self.ips = []
        self.expires = 0.0

    def resolve(self):
        now = time.monotonic()
        if self.ips and now < self.expires:
            return self.ips
        try:
            url = f"https://1.1.1.1/dns-query?name={urllib.parse.quote(self.host)}&type=A"
            req = urllib.request.Request(url, headers={"accept": "application/dns-json"})
            with urllib.request.urlopen(req, timeout=10) as r:
                answers = json.loads(r.read()).get("Answer", [])
            records = [a for a in answers if a.get("type") == 1]
            if not records:
                raise RuntimeError(f"DoH returned no A records for {self.host}")
            self.ips = [a["data"] for a in records]
            self.expires = now + max(min(int(a.get("TTL", 300)) for a in records), self.min_ttl)
        except Exception as e:
            if not self.ips:
                raise
            log.warning("DoH lookup for %s failed (%s); reusing %s", self.host, e, self.ips)
            self.expires = now + self.min_ttl
        return self.ips

    def install(self):
        real_gai = socket.getaddrinfo

        def gai(host, *args, **kwargs):
            if host == self.host:
                return real_gai(self.resolve()[0], *args, **kwargs)
            return real_gai(host, *args, **kwargs)

        socket.getaddrinfo = gai


# --- Sources ----------------------------------------------------------------------------------

class KnockClient:
    def __init__(self, cfg):
        self.cfg = cfg
        self.etag = None
        self.cached = None

    def entries(self):
        headers = {
            "Authorization": f"Bearer {self.cfg.sync_token}",
            "CF-Access-Client-Id": self.cfg.cf_id,
            "CF-Access-Client-Secret": self.cfg.cf_secret,
            "Accept": "application/json",
        }
        if self.etag and self.cached is not None:
            headers["If-None-Match"] = self.etag
        try:
            rows, resp_headers = http_json("GET", f"{self.cfg.knock_url}/list", headers)
        except urllib.error.HTTPError as e:
            if e.code == 304 and self.cached is not None:
                return list(self.cached)
            raise
        if not isinstance(rows, list):
            raise RuntimeError(f"unexpected /list payload: {str(rows)[:200]}")
        self.cached = [r["entry"] for r in rows]
        self.etag = resp_headers.get("ETag")
        return list(self.cached)


def parse_static_lines(lines):
    """Split static-file lines into (ips/cidrs, hostnames). '#' starts a comment; ',' or space separate."""
    ips, hosts = [], []
    for line in lines:
        for token in line.split("#", 1)[0].replace(",", " ").split():
            try:
                ipaddress.ip_network(token, strict=False)
                ips.append(token)
            except ValueError:
                hosts.append(token)
    return ips, hosts


def resolve_host(host):
    out = set()
    for fam, *_, addr in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM):
        if fam == socket.AF_INET:
            out.add(addr[0])
        elif fam == socket.AF_INET6:
            out.add(f"{addr[0]}/64")
    return sorted(out)


class StaticSource:
    """STATIC_IPS / STATIC_HOSTS env vars plus an optional, hot-reloaded STATIC_FILE."""

    def __init__(self, cfg, resolver=resolve_host):
        self.cfg = cfg
        self.resolver = resolver
        self.file_sig = None
        self.file_ips, self.file_hosts = [], []
        self.resolved = {}
        self.next_resolve = 0.0

    def _load_file(self):
        path = self.cfg.static_file
        if not path or not os.path.isfile(path):
            if self.file_sig is not None:
                log.warning("static file %s disappeared; dropping its entries", path)
                self.file_sig, self.file_ips, self.file_hosts = None, [], []
                self.next_resolve = 0.0
            return
        st = os.stat(path)
        sig = (st.st_mtime_ns, st.st_size)
        if sig == self.file_sig:
            return
        with open(path, encoding="utf-8") as f:
            self.file_ips, self.file_hosts = parse_static_lines(f)
        self.file_sig = sig
        self.next_resolve = 0.0
        log.info("loaded %s: %d address(es), %d hostname(s)", path, len(self.file_ips), len(self.file_hosts))

    def entries(self):
        self._load_file()
        hosts = set(self.cfg.static_hosts) | set(self.file_hosts)
        now = time.monotonic()
        if now >= self.next_resolve:
            for host in hosts:
                try:
                    self.resolved[host] = self.resolver(host)
                except OSError as e:
                    # Keep the last good answer so a DNS blip doesn't lock relatives out.
                    log.warning("can't resolve %s: %s (keeping %s)", host, e, self.resolved.get(host, []))
            self.next_resolve = now + self.cfg.static_refresh
        for host in set(self.resolved) - hosts:
            del self.resolved[host]
        out = list(self.cfg.static_ips) + list(self.file_ips)
        for addrs in self.resolved.values():
            out.extend(addrs)
        return out


# --- Normalisation ----------------------------------------------------------------------------

def canonical(entry):
    """Return (version, canonical string) or None. v4 /32 -> bare address; v6 narrower than /64 -> /64."""
    net = ipaddress.ip_network(str(entry).strip(), strict=False)
    if net.version == 4:
        return 4, str(net.network_address) if net.prefixlen == 32 else str(net)
    if net.prefixlen > 64:
        net = net.supernet(new_prefix=64)
    return 6, str(net)


def normalise(entries):
    v4, v6 = set(), set()
    for e in entries:
        try:
            version, value = canonical(e)
        except ValueError:
            log.warning("skipping bad entry %r", e)
            continue
        if version == 6 and ipaddress.ip_network(value).prefixlen < 64:
            log.warning("refusing over-broad %s", value)
            continue
        if version == 4 and ipaddress.ip_network(value).prefixlen < 8:
            log.warning("refusing over-broad %s", value)
            continue
        (v4 if version == 4 else v6).add(value)
    return v4, v6


# --- UniFi ------------------------------------------------------------------------------------

ITEM_KEYS = ("value", "address", "ip", "cidr")


def item_value(item):
    if isinstance(item, str):
        return item
    for k in ITEM_KEYS:
        if k in item:
            return item[k]
    raise ValueError(f"unknown item shape {item!r} - run --dump and adjust item_value/make_item")


def make_item(template, value):
    """Mirror whatever shape UniFi uses for existing items (string or object)."""
    if isinstance(template, str) or template is None:
        return value
    item = dict(template)
    for k in ITEM_KEYS:
        if k in item:
            item[k] = value
            break
    return item


def _canon_or_raw(value):
    try:
        return canonical(value)[1]
    except ValueError:
        return value


class UniFi:
    def __init__(self, cfg):
        self.base = f"{cfg.unifi_host}/proxy/network/integration/v1/sites/{cfg.site}"
        self.key = cfg.unifi_key
        self.ctx = None if cfg.verify_tls else ssl._create_unverified_context()

    def call(self, method, path, body=None):
        headers = {"X-API-KEY": self.key, "Accept": "application/json"}
        return http_json(method, f"{self.base}{path}", headers, body, self.ctx)[0]

    def get_list(self, list_id):
        return self.call("GET", f"/traffic-matching-lists/{list_id}")

    def sync(self, list_id, want):
        """Make the list equal `want`. Returns True if a PUT was needed."""
        cur = self.get_list(list_id)
        items = cur.get("items") or []
        have = {_canon_or_raw(item_value(i)) for i in items}
        if have == set(want):
            return False
        template = items[0] if items else None
        body = {"type": cur["type"], "name": cur["name"],
                "items": [make_item(template, v) for v in sorted(want)]}
        self.call("PUT", f"/traffic-matching-lists/{list_id}", body)
        log.info("%s: +%s -%s", cur["name"], sorted(set(want) - have), sorted(have - set(want)))
        return True


# --- Main loop --------------------------------------------------------------------------------

class Syncer:
    def __init__(self, cfg, knock, static, unifi, clock=time.monotonic):
        self.cfg = cfg
        self.knock = knock
        self.static = static
        self.unifi = unifi
        self.clock = clock
        self.applied = {}
        self.last_reconcile = None

    def targets(self, v4, v6):
        yield self.cfg.list_v4, v4, 4
        if self.cfg.list_v6:
            yield self.cfg.list_v6, v6, 6

    def cycle(self):
        try:
            entries = self.knock.entries()
        except RetryLater:
            raise
        except Exception as e:  # Worker unreachable: leave UniFi as-is rather than guess
            raise RuntimeError(f"can't reach knock worker: {e}") from e
        v4, v6 = normalise(entries + self.static.entries())
        now = self.clock()
        force = self.last_reconcile is None or now - self.last_reconcile >= self.cfg.reconcile_interval
        for list_id, desired, version in self.targets(v4, v6):
            want = frozenset(desired) or frozenset({SENTINEL[version]})
            if not force and self.applied.get(list_id) == want:
                continue
            try:
                self.unifi.sync(list_id, want)
            except Exception:
                self.applied.pop(list_id, None)
                raise
            self.applied[list_id] = want
        if force:
            self.last_reconcile = now


def touch(path):
    try:
        with open(path, "w") as f:
            f.write(str(time.time()))
    except OSError as e:
        log.debug("can't write health file %s: %s", path, e)


def run(cfg, once=False):
    stop = threading.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: stop.set())

    if cfg.knock_doh:
        DohResolver(urllib.parse.urlsplit(cfg.knock_url).hostname).install()

    syncer = Syncer(cfg, KnockClient(cfg), StaticSource(cfg), UniFi(cfg))
    failures = 0
    log.info("starting: interval=%ss reconcile=%ss lists=%s", cfg.interval, cfg.reconcile_interval,
             ",".join(filter(None, (cfg.list_v4, cfg.list_v6))))
    while not stop.is_set():
        delay = cfg.interval
        try:
            syncer.cycle()
            if failures:
                log.info("recovered after %d failed cycle(s)", failures)
            failures = 0
            touch(cfg.health_file)
        except RetryLater as e:
            failures += 1
            delay = min(max(e.retry_after, cfg.interval), 3600.0)
            log.warning("%s; backing off %.0fs", e, delay)
        except Exception as e:
            failures += 1
            delay = min(cfg.interval * 2 ** failures, cfg.max_backoff)
            log.error("sync failed (%d in a row): %s; retrying in %.0fs", failures, e, delay)
        if once:
            return 1 if failures else 0
        stop.wait(delay + random.uniform(0, min(2.0, delay * 0.1)))
    log.info("stopping")
    return 0


def healthcheck(cfg):
    try:
        age = time.time() - os.stat(cfg.health_file).st_mtime
    except FileNotFoundError:
        print("no successful sync yet")
        return 1
    print(f"last successful sync {age:.0f}s ago (max {cfg.health_max_age:.0f}s)")
    return 0 if age <= cfg.health_max_age else 1


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    g = p.add_mutually_exclusive_group()
    g.add_argument("--once", action="store_true", help="run a single sync and exit")
    g.add_argument("--dump", action="store_true", help="print the current UniFi lists and exit")
    g.add_argument("--healthcheck", action="store_true", help="exit 0 if a sync succeeded recently")
    args = p.parse_args(argv)

    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO").upper(),
                        format="%(asctime)s %(levelname)s %(message)s", stream=sys.stdout)

    if args.healthcheck:
        env = dict(os.environ)
        for k in UNIFI_VARS + KNOCK_VARS:
            env.setdefault(k, "-")
        return healthcheck(Config.from_env(env))

    cfg = Config.from_env(need_knock=not args.dump)
    if args.dump:
        unifi = UniFi(cfg)
        for lid in filter(None, (cfg.list_v4, cfg.list_v6)):
            print(json.dumps(unifi.get_list(lid), indent=2))
        return 0
    return run(cfg, once=args.once)


if __name__ == "__main__":
    sys.exit(main())
