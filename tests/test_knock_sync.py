import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import knock_sync as ks  # noqa: E402


def cfg(**kw):
    base = dict(unifi_host="https://unifi", unifi_key="k", site="s", list_v4="L4", list_v6="L6",
                static_file="", reconcile_interval=300, static_refresh=300)
    base.update(kw)
    return ks.Config(**base)


class FakeKnock:
    def __init__(self, entries):
        self.entries_value = entries
        self.fail = None

    def entries(self):
        if self.fail:
            raise self.fail
        return list(self.entries_value)


class FakeStatic:
    def __init__(self, entries=()):
        self.value = list(entries)

    def entries(self):
        return list(self.value)


class FakeUniFi:
    def __init__(self):
        self.calls = []

    def sync(self, list_id, want, labels=None):
        self.calls.append((list_id, set(want)))
        self.labels = labels
        return True


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


class NormaliseTests(unittest.TestCase):
    def test_canonical_forms(self):
        v4, v6 = ks.normalise(["1.2.3.4", "1.2.3.4/32", "10.0.0.5/24", "2a00:1::1", "2a00:2::/48", "nope"])
        self.assertEqual(v4, {"1.2.3.4", "10.0.0.0/24"})
        self.assertEqual(v6, {"2a00:1::/64"})  # /48 refused as over-broad

    def test_refuses_broad_ipv4(self):
        v4, _ = ks.normalise(["0.0.0.0/0", "8.0.0.0/7"])
        self.assertEqual(v4, set())


class StaticTests(unittest.TestCase):
    def test_parse_static_lines(self):
        pairs = ks.parse_static_lines([
            "# comment", "1.2.3.4  # mum", "5.6.7.0/24, mum.ddns.net", "", "2a00::1 dad.example.com",
            "Anthropic API = 160.79.104.0/21", "Office=203.0.113.10  # overridden by '='",
        ])
        self.assertEqual(pairs, [
            ("1.2.3.4", "mum"), ("5.6.7.0/24", None), ("mum.ddns.net", None), ("2a00::1", None),
            ("dad.example.com", None), ("160.79.104.0/21", "Anthropic API"), ("203.0.113.10", "Office"),
        ])

    def test_parse_entry(self):
        self.assertEqual(ks.parse_entry(" Anthropic API=160.79.104.0/21 "), ("160.79.104.0/21", "Anthropic API"))
        self.assertEqual(ks.parse_entry("1.2.3.4"), ("1.2.3.4", None))
        self.assertEqual(ks.parse_entry("=1.2.3.4"), ("1.2.3.4", None))

    def test_file_and_env_merge_and_keep_last_good_resolution(self):
        answers = {"a.example": ["9.9.9.9"]}

        def resolver(host):
            if host not in answers:
                raise OSError("nxdomain")
            return answers[host]

        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "static.txt")
            with open(path, "w") as f:
                f.write("8.8.8.8  # dns\nMum = a.example\n")
            c = cfg(static_file=path, static_ips=["Office=1.1.1.1"], static_hosts=["b.example"], static_refresh=0)
            answers["b.example"] = ["7.7.7.7"]
            src = ks.StaticSource(c, resolver)
            self.assertEqual(sorted(src.entries()), [
                ("1.1.1.1", "Office"), ("7.7.7.7", "b.example"), ("8.8.8.8", "dns"), ("9.9.9.9", "Mum via a.example"),
            ])
            del answers["a.example"]  # DNS blip
            self.assertIn(("9.9.9.9", "Mum via a.example"), src.entries())
            os.remove(path)
            self.assertEqual(sorted(src.entries()), [("1.1.1.1", "Office"), ("7.7.7.7", "b.example")])


class LabelTests(unittest.TestCase):
    def test_label_map_canonicalises_and_merges(self):
        labels = ks.label_map([("1.2.3.4/32", "knock"), ("1.2.3.4", "Office"), ("1.2.3.4", "Office"),
                               ("2a00::1", "phone"), ("junk", "x"), ("5.5.5.5", None)])
        self.assertEqual(labels, {"1.2.3.4": "knock, Office", "2a00::/64": "phone"})

    def test_sync_log_includes_labels(self):
        u = ks.UniFi(cfg())
        u.call = lambda method, path, body=None: body if method == "PUT" else {
            "type": "IPV4_ADDRESSES", "name": "allow-v4", "items": [{"type": "IP_ADDRESS", "value": "192.0.2.1"}]}
        with self.assertLogs("knock-sync", "INFO") as logs:
            u.sync("L4", {"160.79.104.0/21"}, {"160.79.104.0/21": "Anthropic API", "192.0.2.1": "placeholder"})
        self.assertIn("+['160.79.104.0/21 (Anthropic API)'] -['192.0.2.1 (placeholder)']", logs.output[0])

    def test_syncer_passes_labels(self):
        unifi = FakeUniFi()
        static = FakeStatic([("160.79.104.0/21", "Anthropic API")])
        ks.Syncer(cfg(list_v6=""), FakeKnock(["1.2.3.4"]), static, unifi, Clock()).cycle()
        self.assertEqual(unifi.calls, [("L4", {"1.2.3.4", "160.79.104.0/21"})])
        self.assertEqual(unifi.labels["160.79.104.0/21"], "Anthropic API")
        self.assertEqual(unifi.labels["1.2.3.4"], "knock")


class UniFiItemTests(unittest.TestCase):
    def test_item_shapes(self):
        self.assertEqual(ks.item_value("1.2.3.4"), "1.2.3.4")
        self.assertEqual(ks.item_value({"type": "IP_ADDRESS", "value": "1.2.3.4"}), "1.2.3.4")
        self.assertEqual(ks.item_value({"type": "SUBNET", "value": "10.0.0.0/8"}), "10.0.0.0/8")
        self.assertEqual(ks.item_value({"type": "IP_ADDRESS_RANGE", "start": "1.1.1.1", "stop": "1.1.1.9"}),
                         "1.1.1.1-1.1.1.9")
        tmpl = {"type": "IP_ADDRESS", "value": "x"}
        self.assertEqual(ks.make_item(tmpl, "5.5.5.5"), {"type": "IP_ADDRESS", "value": "5.5.5.5"})
        self.assertEqual(ks.make_item(tmpl, "160.79.104.0/21"), {"type": "SUBNET", "value": "160.79.104.0/21"})
        self.assertEqual(ks.make_item(None, "2001:db8::/64"), {"type": "SUBNET", "value": "2001:db8::/64"})
        self.assertEqual(ks.make_item("1.2.3.4", "5.5.5.5"), "5.5.5.5")

    def test_put_body_mixes_addresses_and_subnets(self):
        u = ks.UniFi(cfg())
        sent = []

        def call(method, path, body=None):
            if method == "PUT":
                sent.append(body)
                return body
            return {"type": "IPV4_ADDRESSES", "name": "knock", "items": [
                {"type": "IP_ADDRESS", "value": "1.2.3.4"},
                {"type": "IP_ADDRESS_RANGE", "start": "9.9.9.1", "stop": "9.9.9.5"}]}

        u.call = call
        v4, _ = ks.normalise(["1.2.3.4", "160.79.104.0/21"])
        self.assertTrue(u.sync("L4", v4))
        self.assertEqual(sent[0], {"type": "IPV4_ADDRESSES", "name": "knock", "items": [
            {"type": "IP_ADDRESS", "value": "1.2.3.4"},
            {"type": "SUBNET", "value": "160.79.104.0/21"}]})

    def test_sync_skips_put_when_equivalent(self):
        u = ks.UniFi(cfg())
        calls = []

        def call(method, path, body=None):
            calls.append(method)
            return {"type": "IPV4", "name": "knock", "items": [{"value": "1.2.3.4/32"}]}

        u.call = call
        self.assertFalse(u.sync("L4", {"1.2.3.4"}))
        self.assertEqual(calls, ["GET"])
        self.assertTrue(u.sync("L4", {"1.2.3.4", "5.6.7.8"}))
        self.assertEqual(calls, ["GET", "GET", "PUT"])


class SyncerTests(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.knock = FakeKnock(["1.2.3.4"])
        self.unifi = FakeUniFi()
        self.syncer = ks.Syncer(cfg(), self.knock, FakeStatic(["5.5.5.5"]), self.unifi, self.clock)

    def test_only_touches_unifi_on_change_or_reconcile(self):
        self.syncer.cycle()
        self.assertEqual(self.unifi.calls, [("L4", {"1.2.3.4", "5.5.5.5"}), ("L6", {"2001:db8::/64"})])
        self.unifi.calls.clear()

        self.clock.t += 15
        self.syncer.cycle()
        self.assertEqual(self.unifi.calls, [])

        self.knock.entries_value = ["1.2.3.4", "2a00::1"]
        self.clock.t += 15
        self.syncer.cycle()
        self.assertEqual(self.unifi.calls, [("L6", {"2a00::/64"})])
        self.unifi.calls.clear()

        self.clock.t += 300
        self.syncer.cycle()
        self.assertEqual([c[0] for c in self.unifi.calls], ["L4", "L6"])

    def test_worker_failure_leaves_unifi_alone(self):
        self.knock.fail = OSError("down")
        with self.assertRaises(RuntimeError):
            self.syncer.cycle()
        self.assertEqual(self.unifi.calls, [])

    def test_unifi_failure_forces_retry(self):
        def boom(*args):
            raise OSError("unifi down")

        self.unifi.sync = boom
        with self.assertRaises(OSError):
            self.syncer.cycle()
        self.unifi.sync = FakeUniFi.sync.__get__(self.unifi)
        self.clock.t += 15
        self.syncer.cycle()
        self.assertEqual(self.unifi.calls[0][0], "L4")


class ConfigTests(unittest.TestCase):
    def test_missing_vars(self):
        with self.assertRaises(SystemExit):
            ks.Config.from_env({})

    def test_dump_does_not_need_knock_vars(self):
        env = {"UNIFI_HOST": "https://u/", "UNIFI_API_KEY": "k", "UNIFI_SITE_ID": "s", "UNIFI_LIST_V4_ID": "l"}
        c = ks.Config.from_env(env, need_knock=False)
        self.assertEqual(c.unifi_host, "https://u")
        self.assertEqual(c.interval, 15.0)

    def test_interval_floor(self):
        env = {"UNIFI_HOST": "h", "UNIFI_API_KEY": "k", "UNIFI_SITE_ID": "s", "UNIFI_LIST_V4_ID": "l",
               "SYNC_INTERVAL": "1"}
        self.assertEqual(ks.Config.from_env(env, need_knock=False).interval, 5.0)


if __name__ == "__main__":
    unittest.main()
