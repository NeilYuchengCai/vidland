#!/usr/bin/env python3
"""Grand Duchy of Vidland · local sealed-channel host.

Designated port: 7431 (non-default, low-collision).
All four terminals must be served from the SAME origin so that the
encrypted localStorage register and the Chancellery relay channel
are shared between them. Opening the files via file:// is not supported.

    python serve.py
    VDL_PORT=7431 python serve.py

Optional TLS (needed once terminals are reached from another device over
the LAN: Web Crypto requires a secure context, which a plain http:// LAN
IP is not). Enabled only when VDL_TLS=1. Certificates live under
vidland-data/, which is git-ignored, so private keys never enter the repo.

    VDL_TLS=1 python serve.py
    VDL_TLS=1 VDL_HOST=0.0.0.0 python serve.py
    VDL_TLS=1 VDL_CERT=fullchain.pem VDL_KEY=privkey.pem python serve.py
"""
import http.server
import json
import os
import ssl
import sys
import tempfile
import threading

ROOT = os.path.dirname(os.path.abspath(__file__))
PORT = int(os.environ.get("VDL_PORT", "7431"))
HOST = os.environ.get("VDL_HOST", "127.0.0.1")
TLS = os.environ.get("VDL_TLS", "").strip().lower() in ("1", "true", "yes", "on")

# Local-disk persistence: the encrypted register is mirrored to a real file
# on the host machine so it survives browser restarts and is shared by all
# four terminals. {rev, data{key: value-string}}.
STORE_DIR = os.path.join(ROOT, "vidland-data")
STORE_FILE = os.path.join(STORE_DIR, "store.json")
CERT_FILE = os.environ.get("VDL_CERT", os.path.join(STORE_DIR, "lan-cert.pem"))
KEY_FILE = os.environ.get("VDL_KEY", os.path.join(STORE_DIR, "lan-key.pem"))
_store_lock = threading.Lock()


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

    # ---- local-disk persistence API ----------------------------------
    def _is_api(self):
        return self.path.split("?")[0].startswith("/api/store")

    def do_GET(self):
        if not self._is_api():
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


def main():
    if TLS:
        for f in (CERT_FILE, KEY_FILE):
            if not os.path.isfile(f):
                print("TLS enabled but certificate file missing: %s" % f)
                print("Set VDL_CERT / VDL_KEY, or unset VDL_TLS to serve plain HTTP.")
                sys.exit(1)
    scheme = "https" if TLS else "http"
    shown_host = "127.0.0.1" if HOST in ("0.0.0.0", "", "::") else HOST
    base = "%s://%s:%d" % (scheme, shown_host, PORT)
    try:
        httpd = Server((HOST, PORT), Handler)
    except OSError as exc:
        print("Port %d unavailable: %s" % (PORT, exc))
        print("Set another non-default port: VDL_PORT=NNNN python serve.py")
        sys.exit(1)
    if TLS:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        try:
            ctx.load_cert_chain(CERT_FILE, KEY_FILE)
        except (OSError, ssl.SSLError) as exc:
            print("Certificate load failed: %s" % exc)
            httpd.server_close()
            sys.exit(1)
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    print("=" * 66)
    print("  GRAND DUCHY OF VIDLAND · Chancellery sealed-channel host")
    print("  Origin: %s   (all four terminals share this origin)" % base)
    print("  Transport: %s   Bound: %s:%d" %
          ("HTTPS / TLS" if TLS else "plain HTTP (loopback only)", HOST, PORT))
    print("-" * 66)
    for name, path in PAGES:
        print("  %-24s %s%s" % (name, base, path))
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
