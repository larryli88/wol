import json
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
        self.server = app.make_server(cfg, FakeVerifier())
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
        self.assertEqual(json.loads(body), [
            {"id": "desktop", "name": "Desktop", "mac": MAC, "ip": "127.0.0.1", "online": True}])

    def test_wake_sends_magic_packets(self):
        code, _ = self.req("/api/wake/desktop", "POST",
                           {"Cf-Access-Jwt-Assertion": "good", "X-Requested-With": "wol"})
        self.assertEqual(code, 200)
        for _ in range(3):
            self.assertEqual(self.udp.recv(200), app.magic_packet(MAC))

    def test_wake_rejections(self):
        self.assertEqual(self.req("/api/wake/desktop", "POST", {"X-Requested-With": "wol"})[0], 403)
        self.assertEqual(self.req("/api/wake/desktop", "POST",
                                  {"Cf-Access-Jwt-Assertion": "good"})[0], 400)  # CSRF guard
        self.assertEqual(self.req("/api/wake/nope", "POST",
                                  {"Cf-Access-Jwt-Assertion": "good", "X-Requested-With": "wol"})[0], 404)
        self.udp.settimeout(0.3)
        with self.assertRaises(socket.timeout):
            self.udp.recv(200)


class ConfigTest(unittest.TestCase):
    def test_example_config(self):
        cfg = app.load_config("config.example.toml")
        d = cfg["devices"][0]
        self.assertEqual((d["id"], d["port"], d["broadcast"]), ("desktop", 9, "192.168.1.255"))
        self.assertEqual(cfg["server"]["host"], "127.0.0.1")


if __name__ == "__main__":
    unittest.main()
