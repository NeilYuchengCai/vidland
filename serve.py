#!/usr/bin/env python3
"""Grand Duchy of Vidland · local sealed-channel host.

Designated port: 7431 (non-default, low-collision).
All four terminals must be served from the SAME origin so that the
encrypted localStorage register and the Chancellery relay channel
are shared between them. Opening the files via file:// is not supported.

    python serve.py                      # loopback, plain HTTP (default)
    VDL_TLS=1 python serve.py            # loopback, HTTPS
    VDL_LAN=1 python serve.py            # LAN, HTTPS, host-only admin

LAN mode (VDL_LAN=1) enables TLS and binds 0.0.0.0 so phones/tablets on
the same network can reach the terminals. Web Crypto requires a secure
context, which a plain http:// LAN IP is not, so TLS is mandatory there.

    VDL_LAN=1 python serve.py
    VDL_LAN=1 VDL_ADMIN_LAN=1 python serve.py   # also expose admin (unsafe)

When using the default self-generated certificate, the host renews it
automatically at startup and every 6 hours (before expiry or when the LAN
IP changes), then hot-reloads the TLS context without restarting. The root
CA is reused, so phones never need to reinstall anything. Supplying your
own VDL_CERT / VDL_KEY disables this entirely.

    VDL_CERT_CHECK_SEC=3600 VDL_LAN=1 python serve.py

Certificates and the encrypted register live under vidland-data/, which is
git-ignored, so no private key ever enters the repository.
"""
import datetime
import http.server
import ipaddress
import json
import os
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from urllib.parse import unquote, urlsplit

ROOT = os.path.dirname(os.path.abspath(__file__))
PORT = int(os.environ.get("VDL_PORT", "7431"))
LAN = os.environ.get("VDL_LAN", "").strip().lower() in ("1", "true", "yes", "on")
HOST = os.environ.get("VDL_HOST", "0.0.0.0" if LAN else "127.0.0.1")
TLS = LAN or os.environ.get("VDL_TLS", "").strip().lower() in ("1", "true", "yes", "on")
# The Chancellery private key is inlined in admin.html; only allow that page
# from the host itself unless explicitly overridden.
ADMIN_LAN = os.environ.get("VDL_ADMIN_LAN", "").strip().lower() in ("1", "true", "yes", "on")

# Local-disk persistence: the encrypted register is mirrored to a real file
# on the host machine so it survives browser restarts and is shared by all
# four terminals. {rev, data{key: value-string}}.
STORE_DIR = os.path.join(ROOT, "vidland-data")
STORE_FILE = os.path.join(STORE_DIR, "store.json")
DEFAULT_CERT = os.path.join(STORE_DIR, "lan-cert.pem")
DEFAULT_KEY = os.path.join(STORE_DIR, "lan-key.pem")
CERT_FILE = os.environ.get("VDL_CERT", DEFAULT_CERT)
KEY_FILE = os.environ.get("VDL_KEY", DEFAULT_KEY)
CA_FILE = os.environ.get("VDL_CA", os.path.join(STORE_DIR, "ca.pem"))
# Only auto-manage the certificates we generated ourselves. If the operator
# supplies their own (Let's Encrypt, corporate CA), never touch or overwrite.
MANAGE_CERT = (TLS and CERT_FILE == DEFAULT_CERT and KEY_FILE == DEFAULT_KEY)
CERT_CHECK_SEC = int(os.environ.get("VDL_CERT_CHECK_SEC", "21600"))  # 6h
RENEW_BELOW_DAYS = 30
_store_lock = threading.Lock()

# Static files the four terminals actually reference. Everything else under
# ROOT (vidland-data/*.pem, store.json, .git/, *.py ...) is never served.
PUBLIC_FILES = frozenset({
    "/index.html", "/border.html", "/interior.html", "/admin.html",
    "/vidland-core.js", "/vidland-i18n.js", "/vidland-store.js",
    "/vidland.css", "/ca.pem", "/favicon.ico",
})


def local_addresses():
    """Loopback plus every IPv4 address owned by this machine."""
    out = {"127.0.0.1", "::1"}
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            out.add(info[4][0])
    except Exception:
        pass
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("223.5.5.5", 80))
        out.add(s.getsockname()[0])
        s.close()
    except Exception:
        pass
    return out


def is_local_peer(addr):
    try:
        if ipaddress.ip_address(addr).is_loopback:
            return True
    except ValueError:
        pass
    return addr in local_addresses()


def lan_ipv4s():
    """Non-loopback IPv4 addresses only; IPv6 (::1) is not a cert SAN IP."""
    out = set()
    for a in local_addresses():
        try:
            ip = ipaddress.ip_address(a)
            if ip.version == 4 and not ip.is_loopback:
                out.add(a)
        except ValueError:
            pass
    return out


# ---- self-managed certificate lifecycle ---------------------------------
def cert_days_left(path):
    if not os.path.isfile(path):
        return None
    try:
        d = ssl._ssl._test_decode_cert(path)
        end = datetime.datetime.strptime(d["notAfter"], "%b %d %H:%M:%S %Y %Z")
        return (end - datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)).days
    except Exception:
        return None


def cert_san_ips(path):
    try:
        d = ssl._ssl._test_decode_cert(path)
        return {v for kind, v in d.get("subjectAltName", ()) if kind == "IP Address"}
    except Exception:
        return set()


def cert_needs_renew():
    if not (os.path.isfile(CERT_FILE) and os.path.isfile(KEY_FILE)):
        return True, "证书缺失"
    left = cert_days_left(CERT_FILE)
    if left is None:
        return True, "证书无法解析"
    if left < RENEW_BELOW_DAYS:
        return True, "剩余 %d 天" % left
    missing = lan_ipv4s() - cert_san_ips(CERT_FILE)
    if missing:
        return True, "新 IP %s" % ", ".join(sorted(missing))
    return False, "剩余 %d 天" % left


def ensure_cert(reason="启动检查"):
    """Idempotent: make_cert.py only rewrites when renewal is actually due."""
    need, detail = cert_needs_renew()
    if not need:
        return False, detail
    script = os.path.join(ROOT, "make_cert.py")
    if not os.path.isfile(script):
        return False, "make_cert.py 缺失"
    try:
        r = subprocess.run([sys.executable, script, "--quiet"], cwd=ROOT,
                           capture_output=True, text=True, timeout=60,
                           encoding="utf-8", errors="replace")
        if r.returncode != 0:
            return False, "续签失败: %s" % (r.stderr or "").strip()[:120]
        ok = os.path.isfile(CERT_FILE) and os.path.isfile(KEY_FILE)
        return ok, ("%s → 已自动续签（%s，CA 未变，手机无需操作）" % (reason, detail)
                    if ok else "续签后证书仍缺失")
    except Exception as exc:
        return False, "续签异常: %s" % exc


def cert_watchdog(ctx):
    """Re-check periodically and hot-reload the TLS context in place so a
    long-running host never needs a manual restart to pick up a new cert."""
    while True:
        time.sleep(CERT_CHECK_SEC)
        try:
            need, _ = cert_needs_renew()
            if not need:
                continue
            changed, msg = ensure_cert("定时检查")
            if not changed:
                print("  [cert] %s" % msg, flush=True)
                continue
            ctx.load_cert_chain(CERT_FILE, KEY_FILE)
            print("  [cert] 已热重载 TLS 证书（%s），服务未中断。" % msg, flush=True)
        except Exception as exc:
            print("  [cert] 检查失败（下次重试）: %s" % exc, flush=True)


def _read_store():
    try:
        with open(STORE_FILE, "r", encoding="utf-8") as f:
            obj = json.load(f)
        if not isinstance(obj, dict):
            obj = {"rev": 0, "data": {}}
        obj.setdefault("rev", 0)
        obj.setdefault("data", {})
        return obj
    except Exception:
        return {"rev": 0, "data": {}}


def _write_store(obj):
    os.makedirs(STORE_DIR, exist_ok=True)
    tmp = STORE_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False)
    os.replace(tmp, STORE_FILE)

PAGES = [
    ("Civil Affairs Portal", "/index.html"),
    ("Frontier Inspection", "/border.html"),
    ("Interior Inspection", "/interior.html"),
    ("Chancellery Authority", "/admin.html"),
]


class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=ROOT, **kwargs)

    def end_headers(self):
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
        self.send_header("X-Content-Type-Options", "nosniff")
        super().end_headers()

    def log_message(self, fmt, *args):
        pass

    def _is_api(self):
        return self.path.split("?")[0].startswith("/api/store")

    # ---- static access control ----------------------------------------
    def _serve_ca(self):
        """Hand the root CA to phones so they can trust the LAN certificate."""
        if not os.path.isfile(CA_FILE):
            self.send_error(404, "CA certificate not generated (run make_cert.py)")
            return
        try:
            with open(CA_FILE, "rb") as f:
                body = f.read()
        except OSError:
            self.send_error(500, "CA certificate unreadable")
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/x-x509-ca-cert")
        self.send_header("Content-Disposition", 'attachment; filename="vidland-ca.crt"')
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        raw_path = urlsplit(self.path).path
        path = unquote(raw_path)
        if not self._is_api():
            if path == "/ca.pem":
                if not (TLS and LAN):
                    self.send_error(404, "Not found")
                    return
                return self._serve_ca()
            if path in ("/", ""):
                path = "/index.html"
            if path not in PUBLIC_FILES:
                self.send_error(404, "Not found")
                return
            if path == "/admin.html" and LAN and not ADMIN_LAN and not is_local_peer(self.client_address[0]):
                self.send_error(403, "Authority terminal is host-only")
                return
            return super().do_GET()
        path = self.path.split("?")[0]
        with _store_lock:
            obj = _read_store()
        rev = str(obj.get("rev", 0))
        if path == "/api/store/rev":
            body = rev.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("X-Rev", rev)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        # GET /api/store -> the data dict (the register)
        body = json.dumps(obj.get("data", {}), ensure_ascii=False).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("X-Rev", rev)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_PUT(self):
        if not self._is_api():
            self.send_error(405)
            return
        try:
            length = int(self.headers.get("Content-Length", "0") or "0")
            raw = self.rfile.read(length) if length else b""
            incoming = json.loads(raw.decode("utf-8")) if raw else {}
        except Exception:
            incoming = {}
        with _store_lock:
            obj = _read_store()
            data = obj.get("data", {})
            if not isinstance(data, dict):
                data = {}
            if isinstance(incoming, dict) and incoming.get("vdl") == 1:
                # Key-level delta from a terminal. Applying only the keys this
                # terminal actually changed means a late flush can no longer
                # wipe registers written by the other three terminals.
                changes = incoming.get("set")
                if isinstance(changes, dict):
                    data.update(changes)
                removals = incoming.get("del")
                if isinstance(removals, list):
                    for k in removals:
                        data.pop(k, None)
            elif isinstance(incoming, dict):
                # Legacy full replace, retained for import / administrative use.
                data = incoming
            obj["data"] = data
            obj["rev"] = obj.get("rev", 0) + 1
            _write_store(obj)
            rev = str(obj["rev"])
        body = json.dumps({"rev": rev}).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("X-Rev", rev)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if not self._is_api():
            self.send_error(405)
            return
        path = self.path.split("?")[0]
        if path == "/api/store/reset":
            with _store_lock:
                obj = _read_store()
                obj["data"] = {}
                obj["rev"] = obj.get("rev", 0) + 1
                _write_store(obj)
                rev = str(obj["rev"])
            body = json.dumps({"rev": rev}).encode("utf-8")
            self.send_response(200)
            self.send_header("X-Rev", rev)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_error(404)


class Server(http.server.ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True

    def handle_error(self, request, client_address):
        """A client dropping the TLS connection mid-handshake is normal
        (certificate prompts, page reloads). Do not spam the log for it."""
        exc = sys.exc_info()[1]
        if isinstance(exc, (ConnectionResetError, ConnectionAbortedError,
                            BrokenPipeError, ssl.SSLEOFError)):
            return
        super().handle_error(request, client_address)


def main():
    tls_ctx = None
    if TLS:
        if MANAGE_CERT:
            changed, msg = ensure_cert("启动检查")
            print("  [cert] %s" % msg, flush=True)
        for f in (CERT_FILE, KEY_FILE):
            if not os.path.isfile(f):
                print("TLS enabled but certificate file missing: %s" % f)
                print("Set VDL_CERT / VDL_KEY, or unset VDL_TLS to serve plain HTTP.")
                sys.exit(1)
        tls_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        try:
            tls_ctx.load_cert_chain(CERT_FILE, KEY_FILE)
        except (OSError, ssl.SSLError) as exc:
            print("Certificate load failed: %s" % exc)
            sys.exit(1)
    scheme = "https" if TLS else "http"
    lan_ips = []
    if LAN:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("223.5.5.5", 80))
            lan_ips = [s.getsockname()[0]]
            s.close()
        except Exception:
            lan_ips = sorted(lan_ipv4s())
    shown_host = lan_ips[0] if lan_ips else ("127.0.0.1" if HOST in ("0.0.0.0", "", "::") else HOST)
    base = "%s://%s:%d" % (scheme, shown_host, PORT)
    try:
        httpd = Server((HOST, PORT), Handler)
    except OSError as exc:
        print("Port %d unavailable: %s" % (PORT, exc))
        print("Set another non-default port: VDL_PORT=NNNN python serve.py")
        sys.exit(1)
    if TLS:
        httpd.socket = tls_ctx.wrap_socket(httpd.socket, server_side=True)
        if MANAGE_CERT and CERT_CHECK_SEC > 0:
            threading.Thread(target=cert_watchdog, args=(tls_ctx,),
                             daemon=True, name="vdl-cert-watchdog").start()
    print("=" * 66)
    print("  GRAND DUCHY OF VIDLAND · Chancellery sealed-channel host")
    print("  Origin: %s   (all four terminals share this origin)" % base)
    print("  Transport: %s   Bound: %s:%d" %
          ("HTTPS / TLS" if TLS else "plain HTTP (loopback only)", HOST, PORT))
    if MANAGE_CERT:
        _, detail = cert_needs_renew()
        print("  Cert: 自动续签已开启 · 每 %d 秒检查 · %s · CA 复用（手机免操作）"
              % (CERT_CHECK_SEC, detail))
    elif TLS:
        print("  Cert: 使用外部证书，自动续签已跳过（VDL_CERT / VDL_KEY）")
    print("-" * 66)
    for name, path in PAGES:
        blocked = (path == "/admin.html" and LAN and not ADMIN_LAN)
        print("  %-24s %s%s%s" % (name, base, path, "  [host only]" if blocked else ""))
    if LAN:
        print("-" * 66)
        print("  Mobile / LAN:")
        print("    1. Install the root CA:  %s/ca.pem" % base)
        print("    2. Open:                 %s/index.html" % base)
        if not ADMIN_LAN:
            print("    admin.html is served to this host only (private key protection).")
    print("-" * 66)
    print("  R / Z / A / M protocols are EMPTY until defined in the Authority.")
    print("  Ctrl+C to stop.")
    print("=" * 66, flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n  Registry host stopped.")
        httpd.server_close()


if __name__ == "__main__":
    main()
