import json
import pathlib
import tempfile
import socket
import threading
import time
import unittest
import urllib.error
import urllib.request

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

import app

MAC = "00:11:22:33:44:55"
TEAM = "https://example.cloudflareaccess.com"
AUD = "test-aud"


class FakeVerifier:
    def verify(self, token):
        if token != "good":
            raise ValueError("bad token")
        return {"email": "me@example.com"}


class MagicPacketTest(unittest.TestCase):
    def test_layout(self):
        p = app.magic_packet(MAC)
        self.assertEqual(len(p), 102)
        self.assertEqual(p[:6], b"\xff" * 6)
        self.assertEqual(p[6:], bytes.fromhex("001122334455") * 16)

    def test_dash_separator(self):
        self.assertEqual(app.magic_packet(MAC.replace(":", "-")), app.magic_packet(MAC))

    def test_invalid(self):
        for bad in ["", "00:11:22:33:44", "zz:11:22:33:44:55", "001122334455"]:
            with self.assertRaises(ValueError):
                app.magic_packet(bad)


class StatusTest(unittest.TestCase):
    def test_ping_localhost(self):
        self.assertTrue(app.icmp_ping("127.0.0.1"))

    def test_refused_port_counts_as_online(self):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()  # nothing listening now -> RST
        self.assertTrue(app.tcp_probe("127.0.0.1", port))

    def test_unreachable_is_offline(self):
        # TEST-NET-1, guaranteed unassigned
        self.assertFalse(app.is_online({"ip": "192.0.2.1", "probe_ports": [80]}))


class AccessVerifierTest(unittest.TestCase):
    def setUp(self):
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.v = app.AccessVerifier(TEAM, AUD)
        pub = self.key.public_key()
        self.v.jwks.get_signing_key_from_jwt = lambda token: type("K", (), {"key": pub})()

    def token(self, **over):
        claims = {"aud": [AUD], "iss": TEAM, "email": "me@example.com",
                  "exp": int(time.time()) + 300, **over}
        return jwt.encode(claims, self.key, algorithm="RS256")

    def test_valid(self):
        self.assertEqual(self.v.verify(self.token())["email"], "me@example.com")

    def test_wrong_aud(self):
        with self.assertRaises(jwt.InvalidAudienceError):
            self.v.verify(self.token(aud=["other"]))

    def test_wrong_issuer(self):
        with self.assertRaises(jwt.InvalidIssuerError):
            self.v.verify(self.token(iss="https://evil.cloudflareaccess.com"))

    def test_expired(self):
        with self.assertRaises(jwt.ExpiredSignatureError):
            self.v.verify(self.token(exp=int(time.time()) - 10))

    def test_other_key(self):
        other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        forged = jwt.encode({"aud": [AUD], "iss": TEAM, "exp": int(time.time()) + 300},
                            other, algorithm="RS256")
        with self.assertRaises(jwt.InvalidSignatureError):
            self.v.verify(forged)

    def test_alg_none_rejected(self):
        unsigned = jwt.encode({"aud": [AUD], "iss": TEAM}, None, algorithm="none")
        with self.assertRaises(jwt.InvalidTokenError):
            self.v.verify(unsigned)


class ServerTest(unittest.TestCase):
    def setUp(self):
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp.bind(("127.0.0.1", 0))
        self.udp.settimeout(2)
        cfg = {
            "server": {"host": "127.0.0.1", "port": 0},
            "devices": [{"name": "Desktop", "mac": MAC, "ip": "127.0.0.1",
                         "broadcast": "127.0.0.1", "port": self.udp.getsockname()[1], "id": "desktop"}],
        }
        self.monitor = app.Monitor(cfg["devices"], probe=lambda d: True)
        self.monitor.poll_once()
        self.server = app.make_server(cfg, FakeVerifier(), self.monitor)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.udp.close()

    def req(self, path, method="GET", headers=None):
        r = urllib.request.Request(self.base + path, method=method, headers=headers or {})
        try:
            with urllib.request.urlopen(r, timeout=5) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as e:
            with e:
                return e.code, e.read()

    def test_healthz_needs_no_auth(self):
        self.assertEqual(self.req("/healthz"), (200, b"ok"))

    def test_requires_token(self):
        self.assertEqual(self.req("/")[0], 403)
        self.assertEqual(self.req("/api/devices")[0], 403)
        self.assertEqual(self.req("/", headers={"Cf-Access-Jwt-Assertion": "bad"})[0], 403)

    def test_index_and_devices(self):
        auth = {"Cf-Access-Jwt-Assertion": "good"}
        code, body = self.req("/", headers=auth)
        self.assertEqual(code, 200)
        self.assertIn(b"Wake on LAN", body)
        code, body = self.req("/api/devices", headers=auth)
        self.assertEqual(code, 200)
        [d] = json.loads(body)["devices"]
        self.assertEqual({k: d[k] for k in ("id", "name", "mac", "ip", "online", "since_exact")},
                         {"id": "desktop", "name": "Desktop", "mac": MAC, "ip": "127.0.0.1",
                          "online": True, "since_exact": False})
        code, body = self.req("/logs", headers=auth)
        self.assertEqual(code, 200)
        self.assertIn("最近日志".encode(), body)
        self.assertEqual(self.req("/api/logs")[0], 403)

    def test_wake_sends_magic_packets(self):
        code, _ = self.req("/api/wake/desktop", "POST",
                           {"Cf-Access-Jwt-Assertion": "good", "X-Requested-With": "wol"})
        self.assertEqual(code, 200)
        for _ in range(3):
            self.assertEqual(self.udp.recv(200), app.magic_packet(MAC))
        code, body = self.req("/api/logs", headers={"Cf-Access-Jwt-Assertion": "good"})
        [ev] = json.loads(body)["events"]
        self.assertEqual((ev["kind"], ev["device"], ev["user"]), ("wake", "Desktop", "me@example.com"))

    def test_wake_rejections(self):
        self.assertEqual(self.req("/api/wake/desktop", "POST", {"X-Requested-With": "wol"})[0], 403)
        self.assertEqual(self.req("/api/wake/desktop", "POST",
                                  {"Cf-Access-Jwt-Assertion": "good"})[0], 400)  # CSRF guard
        self.assertEqual(self.req("/api/wake/nope", "POST",
                                  {"Cf-Access-Jwt-Assertion": "good", "X-Requested-With": "wol"})[0], 404)
        self.udp.settimeout(0.3)
        with self.assertRaises(socket.timeout):
            self.udp.recv(200)


class MonitorTest(unittest.TestCase):
    DEV = {"id": "desktop", "name": "Desktop", "mac": MAC}

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.now = 1000.0
        self.up = False

    def tearDown(self):
        self.tmp.cleanup()

    def monitor(self, **kw):
        return app.Monitor([self.DEV], data_dir=self.tmp.name, probe=lambda d: self.up,
                           clock=lambda: self.now, **kw)

    def poll(self, m, up, at):
        self.up, self.now = up, at
        m.poll_once()

    def state(self, m):
        return {k: m.snapshot()[0][k] for k in ("online", "since", "since_exact")}

    def kinds(self, m):
        return [(e["kind"], e["ts"]) for e in m.recent_events()][::-1]

    def test_first_reading_is_not_exact(self):
        m = self.monitor()
        self.assertEqual(self.state(m)["online"], None)
        self.poll(m, False, 1000)
        self.assertEqual(self.state(m), {"online": False, "since": 1000, "since_exact": False})
        self.assertEqual(self.kinds(m), [])

    def test_change_needs_confirmation_and_uses_first_seen_time(self):
        m = self.monitor(confirm=2)
        self.poll(m, False, 1000)
        self.poll(m, True, 1015)   # first sighting
        self.assertFalse(self.state(m)["online"])
        self.poll(m, True, 1030)   # confirmed
        self.assertEqual(self.state(m), {"online": True, "since": 1015, "since_exact": True})
        self.assertEqual(self.kinds(m), [("online", 1030)])

    def test_single_blip_is_ignored(self):
        m = self.monitor(confirm=2)
        self.poll(m, True, 1000)
        self.poll(m, True, 1015)
        self.poll(m, False, 1030)  # one lost ping
        self.poll(m, True, 1045)
        self.poll(m, False, 1060)  # a new, separate miss starts counting again
        self.assertEqual(self.state(m)["online"], True)
        self.assertEqual(self.kinds(m), [])

    def test_state_survives_restart(self):
        m = self.monitor()
        self.poll(m, False, 1000)
        self.poll(m, True, 1015)
        self.poll(m, True, 1030)
        m.record("wake", self.DEV, "me@example.com")
        m2 = self.monitor()
        self.assertEqual([e["kind"] for e in m2.recent_events()], ["wake", "online"])
        self.poll(m2, True, 5000)  # still up after restart: keep the original exact time
        self.assertEqual(self.state(m2), {"online": True, "since": 1015, "since_exact": True})
        self.assertEqual(len(m2.recent_events()), 2)

    def test_change_while_down_is_logged_as_inexact(self):
        m = self.monitor()
        self.poll(m, True, 1000)
        m2 = self.monitor()
        self.poll(m2, False, 9000)
        self.assertEqual(self.state(m2), {"online": False, "since": 9000, "since_exact": False})
        [ev] = m2.recent_events()
        self.assertEqual(ev["kind"], "offline")
        self.assertIn("note", ev)

    def test_event_log_is_bounded_and_compacted(self):
        m = self.monitor(max_events=10)
        for i in range(200):
            self.now = i
            m.record("wake", self.DEV, "x" * 50)
        self.assertEqual(len(m.recent_events()), 10)
        self.assertEqual(m.recent_events()[0]["ts"], 199)
        lines = pathlib.Path(self.tmp.name, "events.jsonl").read_text().splitlines()
        self.assertLess(len(lines), 200)
        self.assertEqual(len(self.monitor(max_events=10).recent_events()), 10)

    def test_unwritable_data_dir_degrades_gracefully(self):
        m = app.Monitor([self.DEV], data_dir="/proc/nope", probe=lambda d: True)
        m.poll_once()
        m.record("wake", self.DEV)
        self.assertEqual(len(m.recent_events()), 1)


class ShutdownTest(unittest.TestCase):
    def setUp(self):
        self.calls = []
        self.result = (True, "")
        self.orig = app.ssh_shutdown
        app.ssh_shutdown = lambda d: (self.calls.append(d["id"]), self.result)[1]
        devices = [
            {"id": "pc", "name": "PC", "mac": MAC, "ip": "127.0.0.1", "broadcast": "127.0.0.1",
             "port": 9, "shutdown": {"user": "u"}},
            {"id": "nas", "name": "NAS", "mac": MAC, "ip": "127.0.0.1", "broadcast": "127.0.0.1", "port": 9},
        ]
        self.monitor = app.Monitor(devices, probe=lambda d: True)
        self.server = app.make_server({"server": {"port": 0}, "devices": devices}, FakeVerifier(), self.monitor)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"

    def tearDown(self):
        app.ssh_shutdown = self.orig
        self.server.shutdown()
        self.server.server_close()

    req = ServerTest.req
    AUTH = {"Cf-Access-Jwt-Assertion": "good", "X-Requested-With": "wol"}

    def test_shutdown_ok_is_logged(self):
        self.assertEqual(self.req("/api/shutdown/pc", "POST", self.AUTH), (200, b'{"ok": true}'))
        self.assertEqual(self.calls, ["pc"])
        [ev] = self.monitor.recent_events()
        self.assertEqual((ev["kind"], ev["device"], ev["user"], ev["ok"]), ("shutdown", "PC", "me@example.com", True))

    def test_shutdown_failure_is_reported(self):
        self.result = (False, "Connection refused")
        code, body = self.req("/api/shutdown/pc", "POST", self.AUTH)
        self.assertEqual((code, json.loads(body)["error"]), (502, "Connection refused"))
        self.assertEqual(self.monitor.recent_events()[0]["error"], "Connection refused")

    def test_shutdown_guards(self):
        self.assertEqual(self.req("/api/shutdown/pc", "POST", {"X-Requested-With": "wol"})[0], 403)
        self.assertEqual(self.req("/api/shutdown/pc", "POST", {"Cf-Access-Jwt-Assertion": "good"})[0], 400)
        self.assertEqual(self.req("/api/shutdown/nas", "POST", self.AUTH)[0], 400)  # not configured
        self.assertEqual(self.req("/api/shutdown/nope", "POST", self.AUTH)[0], 404)
        self.assertEqual(self.calls, [])

    def test_snapshot_flags(self):
        self.assertEqual([d["can_shutdown"] for d in self.monitor.snapshot()], [True, False])

    def test_ssh_command_is_strict(self):
        app.ssh_shutdown = self.orig
        dev = {"ip": "192.0.2.1", "shutdown": {"user": "u", "key": "/k", "known_hosts": "/kh",
                                               "port": 22, "command": "shutdown /s /t 0"}}
        seen = {}
        orig_run = app.subprocess.run
        app.subprocess.run = lambda cmd, **kw: seen.setdefault("cmd", cmd) and type(
            "R", (), {"returncode": 0, "stderr": ""})()
        try:
            self.assertEqual(app.ssh_shutdown(dev), (True, ""))
        finally:
            app.subprocess.run = orig_run
        cmd = " ".join(seen["cmd"])
        for opt in ("BatchMode=yes", "StrictHostKeyChecking=yes", "UserKnownHostsFile=/kh", "IdentitiesOnly=yes"):
            self.assertIn(opt, cmd)
        self.assertEqual(seen["cmd"][-2:], ["u@192.0.2.1", "shutdown /s /t 0"])


class ConfigTest(unittest.TestCase):
    def test_example_config(self):
        cfg = app.load_config("config.example.toml")
        d = cfg["devices"][0]
        self.assertEqual((d["id"], d["port"], d["broadcast"]), ("desktop", 9, "192.168.1.255"))
        self.assertEqual(cfg["server"]["host"], "127.0.0.1")
        self.assertEqual(d["shutdown"], {"user": "your-windows-user", "key": "secrets/id_shutdown",
                                         "known_hosts": "secrets/known_hosts", "port": 22,
                                         "command": "shutdown /s /t 0"})


if __name__ == "__main__":
    unittest.main()
