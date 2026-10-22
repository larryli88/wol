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
import subprocess
import sys
import threading
import time
import tomllib
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import jwt

log = logging.getLogger("wol")

MAC_RE = re.compile(r"^([0-9a-f]{2}[:-]){5}[0-9a-f]{2}$", re.I)
STATIC = Path(__file__).parent
PAGES = {"/": "index.html", "/logs": "logs.html"}
# Optional per-device SSH actions and their default commands (None = required).
SSH_ACTIONS = {"wake": None, "shutdown": "shutdown /s /t 0", "force_off": None}


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


# --- Remote commands over SSH ---------------------------------------------

def ssh_run(device: dict, action: str) -> tuple[bool, str]:
    """Runs the device's `action` (a key of SSH_ACTIONS) command over SSH.

    The target's authorized_keys should pin the key to the same command with
    restrict,command="..." so the key can't be used for anything else. The
    target is the device itself, or `host` when set (e.g. the hypervisor of a
    VM, which is started and stopped with virsh from there).
    """
    sd = device[action]
    host = sd.get("host") or device["ip"]
    cmd = ["ssh", "-i", sd["key"], "-p", str(sd["port"]),
           "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-o", "ConnectTimeout=5",
           "-o", "StrictHostKeyChecking=yes", "-o", f"UserKnownHostsFile={sd['known_hosts']}",
           "-o", "LogLevel=ERROR",
           f"{sd['user']}@{host}", sd["command"]]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
    except (OSError, subprocess.TimeoutExpired) as e:
        return False, str(e)[:300]
    if r.returncode != 0:
        return False, (r.stderr.strip() or f"ssh exited with {r.returncode}")[:300]
    return True, ""


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


# --- Monitor: uptime/downtime tracking and event log -----------------------

class Monitor:
    """Polls devices in the background and records state changes.

    The time a device "came online" is when we first saw it up, so it is only
    as precise as the poll interval. A change must be seen `confirm` polls in
    a row before it counts, so one lost ping doesn't log a fake shutdown.
    """

    def __init__(self, devices, data_dir=None, interval=15.0, confirm=2,
                 max_events=500, probe=is_online, clock=time.time):
        self.devices = devices
        self.interval = interval
        self.confirm = confirm
        self.probe = probe
        self.clock = clock
        self.lock = threading.Lock()
        self.events = deque(maxlen=max_events)
        self.state = {d["id"]: {"online": None, "since": None, "since_exact": False,
                                "checked": None, "pending": None, "pending_at": None,
                                "pending_count": 0} for d in devices}
        self.data_dir = Path(data_dir) if data_dir else None
        if self.data_dir:
            try:
                self.data_dir.mkdir(exist_ok=True)
            except OSError as e:
                log.warning("data dir unavailable, history will not persist: %s", e)
                self.data_dir = None
        self._stored = {}
        self._load()

    # persistence

    def _load(self):
        if not self.data_dir:
            return
        try:
            self._stored = json.loads((self.data_dir / "state.json").read_text())
        except (OSError, ValueError):
            self._stored = {}
        try:
            with open(self.data_dir / "events.jsonl") as f:
                for line in f:
                    try:
                        self.events.append(json.loads(line))
                    except ValueError:
                        pass
        except OSError:
            pass

    def _save_state(self):
        if not self.data_dir:
            return
        keep = {k: {f: v[f] for f in ("online", "since", "since_exact")}
                for k, v in self.state.items() if v["online"] is not None}
        try:
            tmp = self.data_dir / "state.json.tmp"
            tmp.write_text(json.dumps(keep))
            tmp.replace(self.data_dir / "state.json")
        except OSError as e:
            log.warning("could not save state: %s", e)

    def _append_event(self, ev):
        if not self.data_dir:
            return
        path = self.data_dir / "events.jsonl"
        try:
            with open(path, "a") as f:
                f.write(json.dumps(ev, ensure_ascii=False) + "\n")
            # Compact once the file is well past what we keep in memory.
            if path.stat().st_size > 400 * self.events.maxlen:
                tmp = self.data_dir / "events.jsonl.tmp"
                tmp.write_text("".join(json.dumps(e, ensure_ascii=False) + "\n" for e in self.events))
                tmp.replace(path)
        except OSError as e:
            log.warning("could not save event: %s", e)

    # events

    def record(self, kind, device=None, user=None, **extra):
        ev = {"ts": self.clock(), "kind": kind, **extra}
        if device:
            ev["device"] = device["name"]
        if user:
            ev["user"] = user
        with self.lock:
            self.events.append(ev)
            self._append_event(ev)

    def recent_events(self, limit=200):
        with self.lock:
            return list(self.events)[-limit:][::-1]

    # polling

    def observe(self, device, online: bool, now: float):
        st = self.state[device["id"]]
        changed = None
        with self.lock:
            st["checked"] = now
            if st["online"] is None:
                # First reading since start: continue the stored record if it
                # still matches; otherwise the change happened while we were down.
                stored = self._stored.get(device["id"])
                if stored and stored["online"] == online:
                    st.update(online=online, since=stored["since"], since_exact=stored["since_exact"])
                else:
                    st.update(online=online, since=now, since_exact=False)
                    if stored:
                        changed = (online, "while the service was not running")
                self._save_state()
            elif online == st["online"]:
                st.update(pending=None, pending_at=None, pending_count=0)
            else:
                if st["pending"] != online:
                    st.update(pending=online, pending_at=now, pending_count=0)
                st["pending_count"] += 1
                if st["pending_count"] >= self.confirm:
                    st.update(online=online, since=st["pending_at"], since_exact=True,
                              pending=None, pending_at=None, pending_count=0)
                    changed = (online, None)
                    self._save_state()
        if changed:
            self.record("online" if changed[0] else "offline", device,
                        **({"note": changed[1]} if changed[1] else {}))

    def poll_once(self):
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(self.probe, self.devices))
        now = self.clock()
        for d, online in zip(self.devices, results):
            self.observe(d, online, now)

    def run(self):
        while True:
            try:
                self.poll_once()
            except Exception:
                log.exception("poll failed")
            time.sleep(self.interval)

    def start(self):
        threading.Thread(target=self.run, name="monitor", daemon=True).start()

    def snapshot(self):
        with self.lock:
            return [{"id": d["id"], "name": d["name"], "mac": d.get("mac"), "ip": d.get("ip"),
                     "note": d.get("note"), "wake": "ssh" if "wake" in d else "wol",
                     "can_shutdown": "shutdown" in d, "can_force_off": "force_off" in d,
                     **{k: self.state[d["id"]][k] for k in ("online", "since", "since_exact", "checked")}}
                    for d in self.devices]


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
    secrets = Path(os.environ.get("WOL_SECRETS_DIR", "secrets"))
    for d in devices:
        if "mac" in d:
            magic_packet(d["mac"])  # validate early
        elif "wake" not in d:
            raise ValueError(f"{d['name']}: needs a mac (Wake-on-LAN) or a [devices.wake] command")
        d.setdefault("broadcast", "255.255.255.255")
        d.setdefault("port", 9)
        d["id"] = slugify(d["name"])
        for action, default_command in SSH_ACTIONS.items():
            if action not in d:
                continue
            sd = d[action]
            if not sd.get("user") or not (sd.get("host") or d.get("ip")):
                raise ValueError(f"{d['name']}: {action} needs user and a host (or the device ip)")
            if default_command:
                sd.setdefault("command", default_command)
            elif not sd.get("command"):
                raise ValueError(f"{d['name']}: {action} needs a command")
            sd.setdefault("key", str(secrets / f"id_{action}"))
            sd.setdefault("known_hosts", str(secrets / "known_hosts"))
            sd.setdefault("port", 22)
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
    monitor: Monitor | None = None

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
        self._send(code, json.dumps(obj, ensure_ascii=False).encode(), "application/json")

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
        if self.path in PAGES:
            return self._send(200, (STATIC / PAGES[self.path]).read_bytes(), "text/html; charset=utf-8")
        if self.path == "/api/devices":
            return self._json(200, {"now": time.time(), "devices": self.monitor.snapshot()})
        if self.path == "/api/logs":
            return self._json(200, {"now": time.time(), "events": self.monitor.recent_events()})
        self._json(404, {"error": "not found"})

    def do_POST(self):
        user = self._authorize()
        if user is None:
            return
        # Cross-site forms can't set custom headers, so this blocks CSRF.
        if self.headers.get("X-Requested-With") != "wol":
            return self._json(400, {"error": "missing X-Requested-With header"})
        m = re.fullmatch(r"/api/(wake|shutdown|force_off)/([a-z0-9-]+)", self.path)
        device = next((d for d in self.devices if m and d["id"] == m.group(2)), None)
        if device is None:
            return self._json(404, {"error": "unknown device"})
        action = m.group(1)
        if action == "wake" and "wake" not in device:
            send_wol(device["mac"], device["broadcast"], device["port"])
            log.info("wake %s (%s) requested by %s", device["name"], device["mac"], user)
            self.monitor.record("wake", device, user)
            return self._json(200, {"ok": True})
        if action not in device:
            return self._json(400, {"error": f"{action} is not configured for this device"})
        ok, err = ssh_run(device, action)
        log.info("%s %s requested by %s: %s", action, device["name"], user, "ok" if ok else err)
        self.monitor.record(action, device, user, ok=ok, **({"error": err} if err else {}))
        self._json(200 if ok else 502, {"ok": ok, **({"error": err} if err else {})})


def make_server(cfg: dict, verifier: AccessVerifier | None, monitor: Monitor) -> ThreadingHTTPServer:
    server_cfg = cfg.get("server", {})
    handler = type("BoundHandler", (Handler,),
                   {"devices": cfg["devices"], "verifier": verifier, "monitor": monitor})
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

    mon_cfg = cfg.get("monitor", {})
    monitor = Monitor(cfg["devices"], data_dir=os.environ.get("WOL_DATA_DIR", "data"),
                      interval=float(mon_cfg.get("interval", 15)))
    monitor.record("service_start")
    monitor.start()

    server = make_server(cfg, verifier, monitor)
    log.info("listening on %s:%s with %d device(s)", *server.server_address, len(cfg["devices"]))
    server.serve_forever()


if __name__ == "__main__":
    main()
