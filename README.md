# knock-sync

Keeps UniFi **traffic matching lists** in sync with:

1. the dynamic allowlist served by the Cloudflare knock Worker (`GET $KNOCK_URL/list`, behind Cloudflare Access), and
2. a **static allowlist** of IPs/CIDRs/hostnames that are always whitelisted.

It's outbound-only: it polls the Worker and pushes changes to the UniFi Network Integration API. Images are built by GitHub Actions and published to GHCR.

## How often does it poll, and is that safe?

| Call | Default frequency | Notes |
|---|---|---|
| Worker `GET /list` | every `SYNC_INTERVAL` = **15s** (5,760/day) | The Workers free tier allows 100,000 requests/day, so the 5s minimum (17,280/day) also fits. Sends `If-None-Match` so the Worker can reply `304` if it sets an `ETag`. |
| UniFi `GET` list | only when the desired set changes, plus every `RECONCILE_INTERVAL` = **300s** | The periodic check reverts manual edits/drift. |
| UniFi `PUT` list | only when the list really differs | Values are compared canonically (e.g. `1.2.3.4` == `1.2.3.4/32`), so it never rewrites the same list. |
| DNS for `STATIC_HOSTS` | every `STATIC_REFRESH` = **300s** | The last good answer is kept if DNS fails. |
| DoH lookup for the Worker host | honours the record TTL (min 60s) | |

After a failure it backs off exponentially (up to `MAX_BACKOFF`) and honours `Retry-After` on `429`/`503`. If the Worker can't be reached, **UniFi is left as-is**. It never guesses.

## Static allowlist

You can combine either or both:

- **Env vars:** `STATIC_IPS=203.0.113.10,198.51.100.0/28` and `STATIC_HOSTS=mum.ddns.net`
- **File:** `./config/static.txt`, mounted at `/config/static.txt`. It's re-read automatically when it changes, so no restart is needed. See [static.txt.example](static.txt.example).

Over-broad entries are refused (IPv4 shorter than `/8`, IPv6 shorter than `/64`). IPv6 hosts are widened to their `/64`.

## Deploy

1. Push this repo to GitHub. The [build workflow](.github/workflows/build.yml) runs the tests, then builds `linux/amd64` + `linux/arm64` images and pushes them to `ghcr.io/<owner>/knock-sync`:
   - `latest` + `sha-xxxxxxx` on pushes to `main`
   - `1.2.3` / `1.2` for `v1.2.3` tags
   - a weekly rebuild that picks up base-image security fixes
2. If the repo is private, run `docker login ghcr.io` on the host first, with a PAT that has `read:packages`. Alternatively, make the package public under *Packages → knock-sync → Package settings*.
3. On the host:

   ```sh
   cp knock.env.example knock.env      # fill in secrets
   mkdir -p config && cp static.txt.example config/static.txt
   # edit docker-compose.yml: replace OWNER with your GitHub user (lowercase)
   docker compose pull && docker compose up -d
   docker compose logs -f knock-sync
   ```

4. Before the first run, find the UniFi item format:

   ```sh
   docker compose run --rm knock-sync --dump
   ```

   New items copy the shape of the first existing item, so seed each list in the UI with the sentinel (`192.0.2.1` / `2001:db8::/64`).

The container runs as non-root on a read-only filesystem. It has a Docker `HEALTHCHECK`: it's unhealthy if no sync has succeeded in `HEALTH_MAX_AGE`, which defaults to max(120s, 4×interval).

## Configuration

See [knock.env.example](knock.env.example) for every variable. Required ones:
`KNOCK_URL`, `KNOCK_SYNC_TOKEN`, `CF_ACCESS_CLIENT_ID`, `CF_ACCESS_CLIENT_SECRET`, `UNIFI_HOST`, `UNIFI_API_KEY`, `UNIFI_SITE_ID`, `UNIFI_LIST_V4_ID`.

## CLI

```
knock_sync.py                 run forever (container default)
knock_sync.py --once          single sync, exit code 0/1
knock_sync.py --dump          print the UniFi lists and exit
knock_sync.py --healthcheck   used by Docker HEALTHCHECK
```

## Development

```sh
python -m unittest discover -s tests -v
docker build -t knock-sync:dev .
```
