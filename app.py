"""Minimal Wake-on-LAN web service.

Meant to sit behind a Cloudflare Tunnel + Cloudflare Access. It listens on
127.0.0.1 only, and every request (except /healthz) must carry a valid
Cloudflare Access JWT in the Cf-Access-Jwt-Assertion header.
"""

import json
import logging
import os
import re
import socket
import sys
import time
import tomllib
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import jwt

log = logging.getLogger("wol")

MAC_RE = re.compile(r"^([0-9a-f]{2}[:-]){5}[0-9a-f]{2}$", re.I)
INDEX_HTML = (Path(__file__).parent / "index.html").read_bytes()


# --- Wake-on-LAN -----------------------------------------------------------

def magic_packet(mac: str) -> bytes:
    if not MAC_RE.match(mac):
        raise ValueError(f"invalid MAC address: {mac!r}")
    return b"\xff" * 6 + bytes.fromhex(re.sub(r"[:-]", "", mac)) * 16


def send_wol(mac: str, broadcast: str, port: int = 9, repeat: int = 3) -> None:
    packet = magic_packet(mac)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        for _ in range(repeat):
            s.sendto(packet, (broadcast, port))


# --- Online status ---------------------------------------------------------

def icmp_ping(ip: str, timeout: float = 1.0) -> bool | None:
    """Unprivileged ICMP echo (needs net.ipv4.ping_group_range to cover our gid).

    Returns None if ICMP sockets are not permitted here.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP)
    except PermissionError:
        return None
    with s:
        s.settimeout(timeout)
        # type 8 (echo request); the kernel fills in id and checksum.
        s.sendto(b"\x08\x00\x00\x00\x00\x00\x00\x01wol-status", (ip, 0))
        deadline = time.monotonic() + timeout
        while (left := deadline - time.monotonic()) > 0:
            s.settimeout(left)
            try:
                data, _ = s.recvfrom(1024)
            except (socket.timeout, OSError):
                return False
            if data and data[0] == 0:  # echo reply
                return True
        return False


def tcp_probe(ip: str, port: int, timeout: float = 1.0) -> bool:
    """A host that accepts *or refuses* a TCP connection is up."""
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except ConnectionRefusedError:
        return True
    except OSError:
        return False


def is_online(device: dict) -> bool:
    ip = device.get("ip")
    if not ip:
        return False
    if icmp_ping(ip):
        return True
    return any(tcp_probe(ip, p) for p in device.get("probe_ports", []))


# --- Cloudflare Access -----------------------------------------------------

class AccessVerifier:
    def __init__(self, team_domain: str, aud: str):
        self.issuer = team_domain.rstrip("/")
        self.aud = aud
        self.jwks = jwt.PyJWKClient(f"{self.issuer}/cdn-cgi/access/certs", cache_keys=True)

    def verify(self, token: str) -> dict:
        key = self.jwks.get_signing_key_from_jwt(token).key
        return jwt.decode(token, key, algorithms=["RS256"], audience=self.aud, issuer=self.issuer)


# --- Config ----------------------------------------------------------------

def slugify(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-") or "device"


def load_config(path: str) -> dict:
    with open(path, "rb") as f:
        cfg = tomllib.load(f)
    devices = cfg.get("devices", [])
    seen = set()
    for d in devices:
        magic_packet(d["mac"])  # validate early
        d.setdefault("broadcast", "255.255.255.255")
        d.setdefault("port", 9)
        d["id"] = slugify(d["name"])
        if d["id"] in seen:
            raise ValueError(f"duplicate device name: {d['name']!r}")
        seen.add(d["id"])
    cfg["devices"] = devices
    return cfg


# --- HTTP ------------------------------------------------------------------

class Handler(BaseHTTPRequestHandler):
    server_version = "wol"
    sys_version = ""

    # Set by make_server().
    devices: list[dict] = []
    verifier: AccessVerifier | None = None

    def log_message(self, fmt, *args):
        log.info("%s %s", self.address_string(), fmt % args)

    def _send(self, code: int, body: bytes, ctype: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code: int, obj) -> None:
        self._send(code, json.dumps(obj).encode(), "application/json")

    def _authorize(self) -> str | None:
        """Returns the user's email (or 'anonymous'), or None after sending 403."""
        if self.verifier is None:  # explicit insecure mode
            return "anonymous"
        token = self.headers.get("Cf-Access-Jwt-Assertion")
        if not token:
            self._json(403, {"error": "missing Cloudflare Access token"})
            return None
        try:
            claims = self.verifier.verify(token)
        except Exception as e:
            log.warning("rejected Access token: %s", e)
            self._json(403, {"error": "invalid Cloudflare Access token"})
            return None
        return claims.get("email") or claims.get("sub") or "unknown"

    def do_GET(self):
        if self.path == "/healthz":
            return self._send(200, b"ok", "text/plain")
        if self._authorize() is None:
            return
        if self.path == "/":
            return self._send(200, INDEX_HTML, "text/html; charset=utf-8")
        if self.path == "/api/devices":
            with ThreadPoolExecutor(max_workers=8) as pool:
                online = list(pool.map(is_online, self.devices))
            return self._json(200, [
                {"id": d["id"], "name": d["name"], "mac": d["mac"], "ip": d.get("ip"), "online": o}
                for d, o in zip(self.devices, online)
            ])
        self._json(404, {"error": "not found"})

    def do_POST(self):
        user = self._authorize()
        if user is None:
            return
        # Cross-site forms can't set custom headers, so this blocks CSRF.
        if self.headers.get("X-Requested-With") != "wol":
            return self._json(400, {"error": "missing X-Requested-With header"})
        m = re.fullmatch(r"/api/wake/([a-z0-9-]+)", self.path)
        device = next((d for d in self.devices if m and d["id"] == m.group(1)), None)
        if device is None:
            return self._json(404, {"error": "unknown device"})
        send_wol(device["mac"], device["broadcast"], device["port"])
        log.info("wake %s (%s) requested by %s", device["name"], device["mac"], user)
        self._json(200, {"ok": True})


def make_server(cfg: dict, verifier: AccessVerifier | None) -> ThreadingHTTPServer:
    server_cfg = cfg.get("server", {})
    handler = type("BoundHandler", (Handler,), {"devices": cfg["devices"], "verifier": verifier})
    return ThreadingHTTPServer(
        (server_cfg.get("host", "127.0.0.1"), int(server_cfg.get("port", 8099))), handler
    )


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    cfg = load_config(os.environ.get("WOL_CONFIG", "config.toml"))

    access = cfg.get("access", {})
    if os.environ.get("WOL_INSECURE_NO_AUTH") == "1":
        log.warning("WOL_INSECURE_NO_AUTH=1: Cloudflare Access verification is DISABLED")
        verifier = None
    elif access.get("team_domain") and access.get("aud"):
        verifier = AccessVerifier(access["team_domain"], access["aud"])
    else:
        sys.exit("config: [access] team_domain and aud are required (refusing to start without auth)")

    server = make_server(cfg, verifier)
    log.info("listening on %s:%s with %d device(s)", *server.server_address, len(cfg["devices"]))
    server.serve_forever()


if __name__ == "__main__":
    main()
