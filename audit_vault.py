#!/usr/bin/env python3
"""Grand Duchy of Vidland · local-only audit authority.

This module owns three things the terminals never see:

  1. The Chancellery RSA private key, taken out of admin.html and sealed on
     this machine. Terminals no longer decrypt envelopes themselves; they
     POST the sealed envelope to /api/vault/open and receive only plaintext.
  2. A separate, independent 256-bit vault key used to encrypt the audit
     register at rest (AES-256-GCM, one nonce per record, AAD binds each
     record to its own id so records cannot be swapped or replayed).
  3. The token ledger: opaque, high-entropy bearer tokens. Terminals get an
     HttpOnly cookie, never a key and never a token string in JavaScript.

Key wrapping uses Windows DPAPI (CryptProtectData, bound to the current
Windows account). Copying the files to another machine or another account
does not make them readable. On non-Windows hosts it degrades to a 0600
key file and says so at startup.

The audit HTTP endpoint binds 127.0.0.1 ONLY and has NO passphrase.
Authentication is host provenance: loopback socket, peer address, Host
allowlist, Origin / Sec-Fetch-Site checks, no CORS headers (preflight
refused), plus an HttpOnly SameSite=Strict cookie HMAC-signed with a key
derived from the DPAPI-sealed vault key and tied to this process instance.
State-changing POSTs additionally require a custom header. Nothing under
this endpoint is reachable from the LAN, and no key material is ever
serialised into a response.
"""
import base64
import ctypes
import datetime
import hashlib
import hmac
import http.server
import json
import os
import re
import secrets
import threading
import time

ROOT = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(ROOT, "vidland-data")
VAULT_FILE = os.path.join(DATA_DIR, "audit.vault")
VAULT_KEY_FILE = os.path.join(DATA_DIR, "audit.key")
MASTER_KEY_FILE = os.path.join(DATA_DIR, "master.key")
# Legacy builds wrote a random hex passphrase to vidland-data/audit.pass.
# That file is no longer read: the audit endpoint authenticates by host
# provenance (loopback socket, Host/Origin checks, DPAPI-signed session).
# It is safe to delete if present.

try:
    from Crypto.Cipher import AES, PKCS1_OAEP
    from Crypto.Hash import SHA256
    from Crypto.PublicKey import RSA
    CRYPTO_OK = True
except ImportError:
    CRYPTO_OK = False

AUDIT_ENABLED = CRYPTO_OK
# Bind an issued token to the browser that requested it. A stolen bearer
# cookie then fails as soon as it is replayed from a different user agent.
# Peer-IP binding is available but off by default: phones roam between
# WiFi/cellular and a strict IP check would lock legitimate users out.
STRICT_UA = os.environ.get("VDL_STRICT_UA", "1").strip().lower() in (
    "1", "true", "yes", "on")
STRICT_PEER = os.environ.get("VDL_STRICT_PEER", "0").strip().lower() in (
    "1", "true", "yes", "on")
TOKEN_COOKIE = "vdl_audit_t"
SESSION_COOKIE = "vdl_audit_s"
CSRF_HEADER = "X-VDL-Audit"
VAULT_AAD = b"vdl-audit-vault-v1"
RECORD_AAD = b"vdl-audit-record-v1|"
ENTROPY = b"Vidland/AuditAuthority/v1"
KEY_MODE = "DPAPI" if os.name == "nt" else "file-permission"
IS_WINDOWS = os.name == "nt"


# --------------------------------------------------------------------------
# Windows DPAPI key wrapping
# --------------------------------------------------------------------------
if IS_WINDOWS:
    class _DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", ctypes.c_ulong),
                    ("pbData", ctypes.POINTER(ctypes.c_ubyte))]

    _crypt32 = ctypes.windll.crypt32
    _kernel32 = ctypes.windll.kernel32
    _kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    _kernel32.LocalFree.restype = ctypes.c_void_p
    _crypt32.CryptProtectData.argtypes = [
        ctypes.POINTER(_DATA_BLOB), ctypes.c_wchar_p,
        ctypes.POINTER(_DATA_BLOB), ctypes.c_void_p, ctypes.c_void_p,
        ctypes.c_ulong, ctypes.POINTER(_DATA_BLOB)]
    _crypt32.CryptProtectData.restype = ctypes.c_int
    _crypt32.CryptUnprotectData.argtypes = [
        ctypes.POINTER(_DATA_BLOB), ctypes.POINTER(ctypes.c_wchar_p),
        ctypes.POINTER(_DATA_BLOB), ctypes.c_void_p, ctypes.c_void_p,
        ctypes.c_ulong, ctypes.POINTER(_DATA_BLOB)]
    _crypt32.CryptUnprotectData.restype = ctypes.c_int


def _blob(data):
    buf = (ctypes.c_ubyte * len(data)).from_buffer_copy(data)
    return _DATA_BLOB(len(data), buf), buf


def dpapi_protect(data):
    if not IS_WINDOWS:
        return b"RAW1" + data
    src, src_buf = _blob(data)
    ent, ent_buf = _blob(ENTROPY)
    out = _DATA_BLOB()
    # CRYPTPROTECT_UI_FORBIDDEN: never pop a prompt on a background server.
    ok = _crypt32.CryptProtectData(ctypes.byref(src), None,
                                   ctypes.byref(ent), None, None,
                                   0x01, ctypes.byref(out))
    if not ok:
        raise OSError("CryptProtectData failed (WinError %d)" %
                      ctypes.get_last_error())
    try:
        return bytes(bytearray(ctypes.string_at(out.pbData, out.cbData)))
    finally:
        _kernel32.LocalFree(out.pbData)


def dpapi_unprotect(data):
    if not IS_WINDOWS:
        if not data.startswith(b"RAW1"):
            raise ValueError("bad key file format")
        return data[4:]
    src, src_buf = _blob(data)
    ent, ent_buf = _blob(ENTROPY)
    out = _DATA_BLOB()
    ok = _crypt32.CryptUnprotectData(ctypes.byref(src), None,
                                     ctypes.byref(ent), None, None,
                                     0x01, ctypes.byref(out))
    if not ok:
        raise OSError("CryptUnprotectData failed — key file belongs to "
                      "another Windows account or another machine")
    try:
        return bytes(bytearray(ctypes.string_at(out.pbData, out.cbData)))
    finally:
        _kernel32.LocalFree(out.pbData)


def _atomic_write(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)
    if not IS_WINDOWS:
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass


def _b64u(s):
    s = s.encode("ascii") if isinstance(s, str) else s
    return base64.urlsafe_b64decode(s + b"=" * (-len(s) % 4))


def _json_bytes(obj):
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def _now():
    return int(time.time() * 1000)


def _ua_hash(ua):
    return hashlib.sha256((ua or "").encode("utf-8")).hexdigest()[:32]


def _hm(s):
    try:
        h, m = s.split(":")
        return int(h) * 60 + int(m)
    except Exception:
        return 0


def _window_ok(daily, when=None):
    """daily: [["09:00","18:00"], ...] in server local time.
    A start later than the end means an overnight window."""
    if not daily:
        return True
    now = when or datetime.datetime.now()
    cur = now.hour * 60 + now.minute
    for pair in daily:
        try:
            a, b = _hm(pair[0]), _hm(pair[1])
        except Exception:
            continue
        if a <= b:
            if a <= cur <= b:
                return True
        elif cur >= a or cur <= b:      # crosses midnight
            return True
    return False


# --------------------------------------------------------------------------
# Vault
# --------------------------------------------------------------------------
class AuditVault:
    """Thread-safe encrypted audit register and token authority."""

    def __init__(self):
        self.lock = threading.RLock()
        self.boot_epoch = secrets.token_hex(16)
        self._deny_throttle = {}        # (reason, token) -> last logged ms
        self.vault_key = self._load_or_create_key()
        # No human-memorised passphrase. Session cookies are HMAC-signed
        # with a key derived from the DPAPI-sealed vault key and tied to
        # this process instance, so only a page actually served by THIS
        # host can obtain one, and cookies die when the service restarts.
        self.session_key = hmac.new(self.vault_key, b"vdl-audit-session-v1",
                                    hashlib.sha256).digest()
        self.master_pem = self._load_or_create_master()
        self._verify_master()
        self.db = self._load_db()
        # Strict mode authorises a DEVICE rather than just two pages. A
        # policy written by an older build would otherwise lock an approved
        # phone out of the three civil terminals.
        if self.db.get("policy", {}).get("terminals") == ["admin", "entry"]:
            self.db["policy"]["terminals"] = ["*"]
            self._save()
        self._rsa_key = None
        self.log("SYSTEM", "VAULT_OPEN",
                 {"keyMode": KEY_MODE, "crypto": CRYPTO_OK,
                  "auth": "no-passphrase/host-proof"}, internal=True)

    # ---- key lifecycle --------------------------------------------------
    def _load_or_create_key(self):
        if os.path.isfile(VAULT_KEY_FILE):
            with open(VAULT_KEY_FILE, "rb") as f:
                return dpapi_unprotect(f.read())
        key = secrets.token_bytes(32)
        _atomic_write(VAULT_KEY_FILE, dpapi_protect(key))
        return key

    def _public_jwk_from_core(self):
        """Read the fixed public JWK shipped to every terminal, so a migrated
        private key can be verified against it instead of being trusted blind."""
        try:
            with open(os.path.join(ROOT, "vidland-core.js"), "r",
                      encoding="utf-8") as f:
                txt = f.read()
            m = re.search(r"var\s+PUBLIC_JWK\s*=\s*\{(.*?)\}\s*;", txt, re.S)
            if not m:
                return None
            n = re.search(r"\bn:\s*\"([^\"]+)\"", m.group(1))
            e = re.search(r"\be:\s*\"([^\"]+)\"", m.group(1))
            if not (n and e):
                return None
            return (int.from_bytes(_b64u(n.group(1)), "big"),
                    int.from_bytes(_b64u(e.group(1)), "big"))
        except Exception:
            return None

    def _candidate_master_texts(self):
        # 1. An older deployment may still inline the key in admin.html.
        p = os.path.join(ROOT, "admin.html")
        if os.path.isfile(p):
            try:
                with open(p, "r", encoding="utf-8") as f:
                    yield f.read()
            except OSError:
                pass
        # 2. In this repository the key was removed from admin.html during
        #    the audit migration. The last committed copy still carries it,
        #    which also makes a fresh clone on a new machine work as long as
        #    vidland-data/master.key is copied over or history is available.
        try:
            import subprocess
            out = subprocess.run(["git", "-C", ROOT, "show", "HEAD:admin.html"],
                                 capture_output=True, timeout=10)
            if out.returncode == 0:
                yield out.stdout.decode("utf-8", "replace")
        except Exception:
            pass

    def _load_or_create_master(self):
        """Move the Chancellery private JWK out of the browser once, forever.
        The plaintext JWK never lands on disk: it is parsed in memory,
        converted to PEM, DPAPI-sealed, and written out. Candidates are
        checked against the public JWK in vidland-core.js before use."""
        if os.path.isfile(MASTER_KEY_FILE):
            with open(MASTER_KEY_FILE, "rb") as f:
                return dpapi_unprotect(f.read())
        pub = self._public_jwk_from_core()
        for text in self._candidate_master_texts():
            m = re.search(r"var\s+PRIVATE_JWK\s*=\s*(\{.*?\})\s*;", text, re.S)
            if not m:
                continue
            try:
                # Historical copies of admin.html used a JS object literal
                # (unquoted keys), later ones used strict JSON. Read the
                # base64url fields by name so both forms are accepted.
                block = m.group(1)
                fields = {}
                for name in ("n", "e", "d", "p", "q"):
                    f = re.search(r"\b" + name + r"\s*:\s*\"([^\"]+)\"",
                                  block)
                    if not f:
                        raise ValueError("missing JWK field " + name)
                    fields[name] = f.group(1)
                def num(k):
                    return int.from_bytes(_b64u(fields[k]), "big")
                key = RSA.construct((num("n"), num("e"), num("d"),
                                     num("p"), num("q")))
                if pub and (key.n, key.e) != pub:
                    continue          # wrong historical key, keep looking
                pem = key.export_key(format="PEM")
            except Exception:
                continue
            _atomic_write(MASTER_KEY_FILE, dpapi_protect(pem))
            print("  [audit] 主私钥已从页面迁移到本机加密文件，"
                  "并与 core.js 公钥核对一致。", flush=True)
            return pem
        raise RuntimeError(
            "找不到原主私钥。请从原机器拷贝 vidland-data/master.key，"
            "或保留包含旧 admin.html 的 git 历史后重新启动。")

    def _verify_master(self):
        """Warn (do not block) when the sealed private key and the public
        JWK shipped to the terminals have drifted apart — e.g. someone
        restored master.key.old after a rotation."""
        try:
            key = RSA.import_key(self.master_pem)
            pub = self._public_jwk_from_core()
            if pub and (key.n, key.e) != pub:
                print("  [audit] 警告: master.key 与 core.js 的 PUBLIC_JWK "
                      "不一致，新提交的密封详情将无法解开。", flush=True)
        except Exception:
            pass

    # ---- at-rest encryption --------------------------------------------
    def _seal(self, plain, aad):
        nonce = secrets.token_bytes(12)
        c = AES.new(self.vault_key, AES.MODE_GCM, nonce=nonce, mac_len=16)
        c.update(aad)
        ct, tag = c.encrypt_and_digest(plain)
        return {"n": base64.b64encode(nonce).decode(),
                "t": base64.b64encode(tag).decode(),
                "c": base64.b64encode(ct).decode()}

    def _open(self, blob, aad):
        c = AES.new(self.vault_key, AES.MODE_GCM,
                    nonce=base64.b64decode(blob["n"]), mac_len=16)
        c.update(aad)
        return c.decrypt_and_verify(base64.b64decode(blob["c"]),
                                    base64.b64decode(blob["t"]))

    def _empty_db(self):
        return {"v": 1, "requests": {}, "tokens": {}, "devices": {},
                "policy": {"once": False, "hours": 8, "daily": [],
                           "terminals": ["*"], "maxMinutes": 0},
                "rev": 0, "log": []}

    def _load_db(self):
        if not os.path.isfile(VAULT_FILE):
            return self._empty_db()
        try:
            with open(VAULT_FILE, "rb") as f:
                blob = json.loads(f.read().decode("utf-8"))
            return json.loads(self._open(blob, VAULT_AAD).decode("utf-8"))
        except Exception:
            # A tampered or foreign-account vault must not be silently
            # replaced with an empty one: that would erase the audit trail.
            raise RuntimeError("审计库无法解密或完整性校验失败，已拒绝启动。"
                               "请检查是否换了 Windows 账户 / 机器，或文件被改动。")

    def _save(self):
        blob = self._seal(_json_bytes(self.db), VAULT_AAD)
        _atomic_write(VAULT_FILE, _json_bytes(blob))

    # ---- audit records --------------------------------------------------
    def log(self, kind, action, detail, device="", terminal="", peer="",
            internal=False):
        """Each record is separately encrypted with AAD bound to its own id,
        so reordering, deleting or splicing records breaks the GCM tag."""
        with self.lock:
            rid = "LOG-" + secrets.token_hex(8)
            rec = {"id": rid, "at": _now(), "kind": kind, "action": action,
                   "device": device, "terminal": terminal, "peer": peer,
                   "detail": detail}
            blob = self._seal(_json_bytes(rec), RECORD_AAD + rid.encode("ascii"))
            self.db["log"].append({"id": rid, "blob": blob})
            if len(self.db["log"]) > 5000:
                self.db["log"] = self.db["log"][-5000:]
            self._save()
            return rid

    def logs(self, limit=200):
        with self.lock:
            out = []
            for item in self.db["log"][-limit:]:
                try:
                    raw = self._open(item["blob"],
                                     RECORD_AAD + item["id"].encode("ascii"))
                    out.append(json.loads(raw.decode("utf-8")))
                except Exception:
                    out.append({"id": item["id"], "action": "TAMPERED",
                                "at": 0, "kind": "ALERT",
                                "detail": {"error": "integrity check failed"}})
            return list(reversed(out))

    # ---- Chancellery envelope -------------------------------------------
    def open_envelope(self, env):
        """Server-side hybrid decryption. The RSA private key never leaves
        this process; the caller receives only plaintext JSON."""
        if not CRYPTO_OK:
            raise RuntimeError("PyCryptodome is required for /api/vault/open")
        if self._rsa_key is None:
            self._rsa_key = RSA.import_key(self.master_pem)
        raw = PKCS1_OAEP.new(self._rsa_key, hashAlgo=SHA256).decrypt(
            _b64u(env["ek"]))
        iv, ct = _b64u(env["iv"]), _b64u(env["ct"])
        aes = AES.new(raw, AES.MODE_GCM, nonce=iv, mac_len=16)
        return json.loads(aes.decrypt_and_verify(ct[:-16], ct[-16:]).decode("utf-8"))

    # ---- host-proven sessions (no passphrase) ---------------------------
    def issue_session(self):
        payload = {"e": self.boot_epoch, "n": secrets.token_hex(8)}
        raw = base64.urlsafe_b64encode(
            _json_bytes(payload)).decode("ascii").rstrip("=")
        sig = hmac.new(self.session_key, raw.encode("ascii"),
                       hashlib.sha256).hexdigest()[:32]
        return raw + "." + sig

    def session_ok(self, sid):
        if not sid or "." not in sid:
            return False
        raw, sig = sid.split(".", 1)
        want = hmac.new(self.session_key, raw.encode("ascii"),
                        hashlib.sha256).hexdigest()[:32]
        if not hmac.compare_digest(sig, want):
            return False
        try:
            payload = json.loads(base64.urlsafe_b64decode(
                raw + "=" * (-len(raw) % 4)).decode("utf-8"))
            return payload.get("e") == self.boot_epoch
        except Exception:
            return False

    # ---- terminal side --------------------------------------------------
    @staticmethod
    def token_hash(token):
        return hashlib.sha256(token.encode("ascii")).hexdigest()

    def enter(self, peer, device, terminal, ua, token, local=False,
              mode="browser"):
        """Every entry into admin / entry is recorded. A local (loopback)
        terminal is always admitted and needs no token at all. `mode`
        records how the page was launched (browser / standalone), because a
        home-screen web app may use a separate cookie and storage container
        and therefore appears as a second device on the same phone."""
        with self.lock:
            if local:
                self.log("ACCESS", "LOCAL_ADMIT", {"ua": ua[:180]},
                         device, terminal, peer)
                return {"state": "LOCAL", "local": True}
            if token:
                # STRICT_UA binds a token to the User-Agent that applied for
                # it. Pass `ua` through: without it validate() hashes an empty
                # string, rejects an otherwise valid token and opens a SECOND
                # pending request for a device that was already approved.
                # That second request used to cover a real terminal page with
                # a "waiting for approval" card and, worse, kept a cut page
                # alive because its poll followed the PENDING request id
                # instead of the revoked token.
                ok, reason, tid = self.validate(peer, token, device, terminal,
                                                "/api/audit/enter", False, ua)
                if ok:
                    rec = self.db["tokens"].get(self.token_hash(token), {})
                    self.log("ACCESS", "TOKEN_ADMIT",
                             {"token": tid[:12], "ua": ua[:180]},
                             device, terminal, peer)
                    # Give the gate its request id back, so its 1 s poll can
                    # use /api/audit/status instead of re-submitting an entry
                    # (which would write one audit record every second).
                    return {"state": "GRANTED", "tokenId": tid,
                            "requestId": rec.get("requestId", "")}
                self.log("ACCESS", "TOKEN_REJECTED", {"reason": reason},
                         device, terminal, peer)
            # One pending request per DEVICE, not per terminal. Opening
            # admin.html and entry.html on the same phone must produce a
            # single approval item; one approval covers both protected
            # terminals. This also stops a refresh loop flooding the queue.
            for rid, req in self.db["requests"].items():
                if (req.get("state") == "PENDING"
                        and req.get("device") == device):
                    req["lastSeen"] = _now()
                    req["hits"] = req.get("hits", 1) + 1
                    req["mode"] = mode[:24]
                    self._save()
                    return {"state": "PENDING", "requestId": rid}
            # An approval may already exist while the HttpOnly cookie has not
            # yet reached the browser (reload race). Never open a duplicate
            # approval item for the same device + terminal; reuse it so the
            # operator sees exactly one request.
            for rid, req in self.db["requests"].items():
                if (req.get("state") in ("ISSUED", "APPROVED")
                        and req.get("device") == device
                        and req.get("terminal") == terminal):
                    req["lastSeen"] = _now()
                    self._save()
                    return {"state": "PENDING", "requestId": rid}
            rid = "REQ-" + secrets.token_hex(8)
            self.db["requests"][rid] = {
                "id": rid, "at": _now(), "lastSeen": _now(), "hits": 1,
                "device": device, "terminal": terminal, "peer": peer,
                "ua": ua[:240], "state": "PENDING", "issued": None,
                "mode": mode[:24], "note": ""}
            self._save()
            self.log("REQUEST", "TOKEN_APPLIED",
                     {"requestId": rid, "ua": ua[:180]}, device, terminal, peer)
            return {"state": "PENDING", "requestId": rid}

    def _status_by_token(self, token, device, expect_rid=None):
        """Read-only status for a gate that already holds a live cookie but
        has no request id (a fresh tab, or a reload after approval). Deliberately
        does NOT call validate(): a 1 s poll must not increment usage counters,
        consume a single-use token, or write to the encrypted vault."""
        rec = self.db["tokens"].get(self.token_hash(token or ""))
        if not rec:
            return {"state": "UNKNOWN"}
        if expect_rid and rec.get("requestId") != expect_rid:
            return {"state": "UNKNOWN"}
        dev = self.db["devices"].get(rec["device"], {})
        now = _now()
        if rec.get("revoked") or dev.get("blocked"):
            return {"state": "REVOKED", "reason": "OPERATOR_CUT"}
        if device and rec["device"] != device:
            return {"state": "REVOKED", "reason": "DEVICE_MISMATCH"}
        if now < rec.get("notBefore", 0) or now > rec.get("notAfter", 0):
            return {"state": "EXPIRED", "reason": "EXPIRED"}
        if not _window_ok(rec.get("daily", [])):
            return {"state": "EXPIRED", "reason": "OUTSIDE_WINDOW"}
        if rec.get("maxMinutes") and now - rec["createdAt"] > \
                rec["maxMinutes"] * 60000:
            return {"state": "EXPIRED", "reason": "SESSION_LIMIT"}
        return {"state": "GRANTED", "tokenId": rec["id"],
                "requestId": rec.get("requestId", "")}

    def static_access_ok(self, token, terminal):
        """Side-effect-free check used before delivering a terminal page.
        Must NOT go through validate(): doing so would consume a single-use
        token on the very first HTTP request and break the page it just
        authorised, or inflate usage counters on every page load."""
        st = self._status_by_token(token, None)
        if st.get("state") != "GRANTED":
            return False
        rec = self.db["tokens"].get(self.token_hash(token or ""), {})
        terms = rec.get("terminals", [])
        return "*" in terms or terminal in terms

    def has_live_token(self, token):
        """Pure check for shared static assets: any valid, uncut token is
        enough, regardless of which terminals its policy names."""
        return self._status_by_token(token, None).get("state") == "GRANTED"

    def can_open_sealed(self, token):
        """Whether this token may receive the RSA-sealed envelope payloads.
        Only the Authority needs them; the three civil terminals replay the
        broadcast `meta` and never read `payload`."""
        rec = self.db["tokens"].get(self.token_hash(token or ""), {})
        if not rec or rec.get("revoked"):
            return False
        terms = rec.get("terminals", [])
        return "*" in terms or "admin" in terms

    def status(self, rid, device, token, local=False):
        """Mobile gate polls this. On approval the ONE-TIME plaintext token
        is handed to the main server, which sets an HttpOnly cookie; it is
        then erased here so only its SHA-256 digest remains on disk."""
        with self.lock:
            if local:
                return {"state": "LOCAL"}, None
            if not rid and token:
                return self._status_by_token(token, device), None
            req = self.db["requests"].get(rid)
            if not req:
                return {"state": "UNKNOWN"}, None
            if req.get("device") != device:
                return {"state": "UNKNOWN"}, None
            # A cut / expired cookie must win over a stale request id. The
            # old behaviour returned PENDING forever for a page whose token
            # had already been revoked, so the terminal stayed on a waiting
            # card with decrypted register data still in memory. A request
            # filed AFTER the cut is a deliberate re-application; let it wait
            # for a fresh approval (which replaces the stale cookie).
            if token:
                tok = self._status_by_token(token, device)
                if tok.get("state") != "GRANTED":
                    rec = self.db["tokens"].get(self.token_hash(token)) or {}
                    cut_at = rec.get("revokedAt") or rec.get("notAfter") or 0
                    fresh = (req.get("state") == "PENDING"
                             and req.get("at", 0) > cut_at)
                    if not fresh:
                        return tok, None
            if req["state"] == "APPROVED" and req.get("issued"):
                issued = req.pop("issued")
                req["state"] = "ISSUED"
                self._save()
                self.log("TOKEN", "TOKEN_ISSUED",
                         {"requestId": rid, "tokenId": issued["id"]},
                         device, req.get("terminal"), req.get("peer", ""))
                return {"state": "GRANTED", "tokenId": issued["id"],
                        "requestId": rid}, issued["token"]
            if req["state"] == "ISSUED":
                if token:
                    return self._status_by_token(token, device, rid), None
                return {"state": "PENDING", "requestId": rid}, None
            if req["state"] == "REJECTED":
                return {"state": "REJECTED", "reason": req.get("note", "")}, None
            if req["state"] == "REVOKED":
                return {"state": "REVOKED", "reason": req.get("note", "")}, None
            return {"state": req["state"]}, None

    def validate(self, peer, token, device, terminal, path, record=True,
                 ua=""):
        """Called by the main server for EVERY /api/store and /api/vault/open
        request from a non-loopback peer. Returns (ok, reason, token_id)."""
        with self.lock:
            th = self.token_hash(token or "")
            rec = self.db["tokens"].get(th)
            if not rec:
                return self._deny("NO_TOKEN", peer, device, terminal, path, record)
            if rec.get("revoked"):
                return self._deny("REVOKED", peer, device, terminal, path, record, rec["id"])
            dev = self.db["devices"].get(rec["device"], {})
            if dev.get("blocked"):
                return self._deny("DEVICE_BLOCKED", peer, device, terminal, path, record, rec["id"])
            if device and rec["device"] != device:
                return self._deny("DEVICE_MISMATCH", peer, device, terminal, path, record, rec["id"])
            if STRICT_UA and rec.get("uaHash") and _ua_hash(ua) != rec["uaHash"]:
                return self._deny("UA_MISMATCH", peer, device, terminal, path, record, rec["id"])
            if STRICT_PEER and rec.get("peer") and peer and rec["peer"] != peer:
                return self._deny("PEER_MISMATCH", peer, device, terminal, path, record, rec["id"])
            terms = rec.get("terminals", [])
            if terminal and "*" not in terms and terminal not in terms:
                return self._deny("TERMINAL_DENIED", peer, device, terminal, path, record, rec["id"])
            now = _now()
            if now < rec.get("notBefore", 0) or now > rec.get("notAfter", 0):
                return self._deny("EXPIRED", peer, device, terminal, path, record, rec["id"])
            if not _window_ok(rec.get("daily", [])):
                return self._deny("OUTSIDE_WINDOW", peer, device, terminal, path, record, rec["id"])
            limit = rec.get("maxMinutes", 0) or 0
            if limit and now - rec["createdAt"] > limit * 60000:
                return self._deny("SESSION_LIMIT", peer, device, terminal, path, record, rec["id"])
            rec["lastSeen"] = now
            rec["uses"] = rec.get("uses", 0) + 1
            if rec.get("once") and rec["uses"] > 1:
                rec["revoked"] = True
                rec["revokedAt"] = now
                self.db["rev"] += 1
                self.log("TOKEN", "ONE_SHOT_CONSUMED", {"tokenId": rec["id"]},
                         device, terminal, peer)
            # /api/store/rev is polled once a second by every open terminal.
            # Persist usage counters at most every 5 s instead of hammering
            # the encrypted vault with a full rewrite on each poll.
            elif now - rec.get("_savedAt", 0) > 5000:
                rec["_savedAt"] = now
                self._save()
            return True, "OK", rec["id"]

    def _deny(self, reason, peer, device, terminal, path, record, tid=""):
        if record:
            key = (reason, tid)
            last = self._deny_throttle.get(key, 0)
            if _now() - last > 5000:
                self._deny_throttle[key] = _now()
                self.log("DENY", reason, {"path": path, "tokenId": tid},
                         device, terminal, peer)
        return False, reason, tid

    # ---- audit authority side -------------------------------------------
    def approve(self, rid, policy):
        with self.lock:
            req = self.db["requests"].get(rid)
            if not req or req["state"] != "PENDING":
                return {"ok": False, "error": "申请不存在或已处理"}
            base = dict(self.db.get("policy", {}))
            base.update(policy or {})
            hours = max(1, min(int(base.get("hours", 8)), 24 * 30))
            # An approval must at minimum unlock the terminal that sent the
            # request, otherwise the gate reloads into another gate forever.
            terms = base.get("terminals") or ["*"]
            if "*" not in terms:
                src = req.get("terminal") or ""
                if src and src not in terms:
                    terms = list(terms) + [src]
                    base["terminals"] = terms
            now = _now()
            token = secrets.token_urlsafe(32)
            tid = "TKN-" + secrets.token_hex(6)
            rec = {
                "id": tid, "hash": self.token_hash(token),
                "device": req["device"], "terminals": terms,
                "requestId": rid, "createdAt": now, "lastSeen": now,
                "peer": req.get("peer", ""),
                "uaHash": _ua_hash(req.get("ua", "")),
                "notBefore": now, "notAfter": now + hours * 3600000,
                "daily": base.get("daily", []), "maxMinutes":
                max(0, int(base.get("maxMinutes", 0))),
                "once": bool(base.get("once", False)),
                "revoked": False, "revokedAt": None, "uses": 0}
            self.db["tokens"][rec["hash"]] = rec
            dev = self.db["devices"].setdefault(req["device"], {
                "id": req["device"], "label": "", "blocked": False,
                "firstSeen": now, "lastSeen": now, "policy": {}})
            dev["lastSeen"] = now
            dev["blocked"] = False
            dev["policy"] = {k: base.get(k) for k in
                             ("hours", "daily", "terminals", "maxMinutes", "once")}
            req["state"] = "APPROVED"
            req["approvedAt"] = now
            req["tokenId"] = tid
            req["issued"] = {"id": tid, "token": token}
            self._save()
            self.log("DECISION", "APPROVED",
                     {"requestId": rid, "tokenId": tid, "hours": hours,
                      "daily": rec["daily"], "terminals": rec["terminals"]},
                     req["device"], req.get("terminal"), req.get("peer", ""))
            return {"ok": True, "tokenId": tid}

    def deny(self, rid, note=""):
        with self.lock:
            req = self.db["requests"].get(rid)
            if not req or req["state"] != "PENDING":
                return {"ok": False, "error": "申请不存在或已处理"}
            req["state"] = "REJECTED"
            req["note"] = note[:300]
            req["decidedAt"] = _now()
            self._save()
            self.log("DECISION", "REJECTED",
                     {"requestId": rid, "note": req["note"]},
                     req["device"], req.get("terminal"), req.get("peer", ""))
            return {"ok": True}

    def revoke(self, target):
        """target: {"tokenId": ...} | {"device": ...} | {"all": true}.
        Immediate: every subsequent API call is refused, and the shared
        rev counter lets the mobile gate lock its screen on the next poll."""
        with self.lock:
            n = 0
            want = (target or {})
            for rec in self.db["tokens"].values():
                hit = (want.get("all") or
                       (want.get("tokenId") and rec["id"] == want["tokenId"]) or
                       (want.get("device") and rec["device"] == want["device"]))
                if hit and not rec.get("revoked"):
                    rec["revoked"] = True
                    rec["revokedAt"] = _now()
                    n += 1
            for rid, req in self.db["requests"].items():
                if (want.get("all") or
                        (want.get("device") and req["device"] == want["device"]) or
                        (want.get("tokenId") and req.get("tokenId") == want["tokenId"])):
                    if req["state"] in ("APPROVED", "ISSUED", "PENDING"):
                        req["state"] = "REVOKED"
                        req["note"] = "OPERATOR_CUT"
                        req.pop("issued", None)
            self.db["rev"] += 1
            self._save()
            self.log("DECISION", "CUT",
                     {"target": want, "tokensRevoked": n, "rev": self.db["rev"]})
            return {"ok": True, "revoked": n, "rev": self.db["rev"]}

    def set_device(self, device, patch):
        with self.lock:
            dev = self.db["devices"].setdefault(device, {
                "id": device, "label": "", "blocked": False,
                "firstSeen": _now(), "lastSeen": _now(), "policy": {}})
            for k in ("label", "blocked"):
                if k in (patch or {}):
                    dev[k] = patch[k]
            if isinstance(patch.get("policy"), dict):
                dev.setdefault("policy", {}).update(patch["policy"])
            dev["lastSeen"] = _now()
            # Blocking a device also kills its live tokens right now.
            if dev.get("blocked"):
                for rec in self.db["tokens"].values():
                    if rec["device"] == device and not rec.get("revoked"):
                        rec["revoked"] = True
                        rec["revokedAt"] = _now()
                self.db["rev"] += 1
            self._save()
            self.log("DECISION", "DEVICE_POLICY",
                     {"device": device, "patch": patch or {}})
            return {"ok": True}

    def set_default_policy(self, patch):
        with self.lock:
            self.db.setdefault("policy", {}).update(patch or {})
            self._save()
            self.log("DECISION", "DEFAULT_POLICY", {"patch": patch or {}})
            return {"ok": True}

    def device_blocked(self, device):
        if not device:
            return False
        with self.lock:
            return bool(self.db["devices"].get(device, {}).get("blocked"))

    def purge_all(self):
        """One-click zeroing of the WHOLE audit ledger: pending requests,
        every issued token, every registered device, every audit record and
        the default policy. Deliberately does NOT touch the sealed key files
        (master.key / audit.key) or the civic register (store.json) — the
        host must remain usable afterwards. No PURGE record is written, so
        the log really ends up empty."""
        with self.lock:
            cleared = {
                "requests": len(self.db.get("requests", {})),
                "tokens": len(self.db.get("tokens", {})),
                "devices": len(self.db.get("devices", {})),
                "records": len(self.db.get("log", [])),
            }
            self.db = self._empty_db()
            self._deny_throttle.clear()
            self._save()
            print("  [audit] 审计台账已一键清零：%d 申请 / %d 令牌 / "
                  "%d 设备 / %d 记录。密钥文件与政务登记册未改动。"
                  % (cleared["requests"], cleared["tokens"],
                     cleared["devices"], cleared["records"]), flush=True)
            return {"ok": True, "cleared": cleared}

    def data_view(self):
        """Never returns a plaintext token or the vault key."""
        with self.lock:
            reqs = []
            for r in self.db["requests"].values():
                c = dict(r)
                c.pop("issued", None)
                reqs.append(c)
            reqs.sort(key=lambda x: x.get("at", 0), reverse=True)
            toks = []
            for r in self.db["tokens"].values():
                c = dict(r)
                c.pop("hash", None)
                toks.append(c)
            toks.sort(key=lambda x: x.get("createdAt", 0), reverse=True)
            return {"requests": reqs[:200], "tokens": toks[:200],
                    "devices": list(self.db["devices"].values()),
                    "policy": self.db.get("policy", {}),
                    "rev": self.db.get("rev", 0),
                    "logs": self.logs(120), "keyMode": KEY_MODE}


# --------------------------------------------------------------------------
# Loopback-only audit HTTP endpoint
# --------------------------------------------------------------------------
class AuditHandler(http.server.BaseHTTPRequestHandler):
    """Bound to 127.0.0.1 exclusively. There is NO passphrase to remember.

    The credential is the ability to reach this loopback endpoint from a
    page the endpoint served itself. Defence layers, in order:

      1. socket bound to 127.0.0.1 -> other machines cannot connect at all;
      2. peer address re-checked on every request;
      3. Host allowlist -> DNS rebinding with a foreign hostname fails;
      4. Origin / Sec-Fetch-Site -> a page on another origin cannot call us;
      5. no CORS headers and OPTIONS refused -> a cross-origin fetch carrying
         the custom header never gets past preflight;
      6. HttpOnly / SameSite=Strict session cookie, HMAC-signed with a key
         derived from the DPAPI-sealed vault key and tied to this process;
      7. every state-changing POST requires X-VDL-Audit: 1.

    A forged or replayed cookie fails the HMAC; a cookie from a previous
    run fails the boot-epoch check. The operator types nothing at all.
    """

    vault = None
    allowed_hosts = frozenset()
    allowed_origins = frozenset()
    page_file = ""
    lexicon_file = ""

    def log_message(self, fmt, *args):
        pass

    def _peer_ok(self):
        return self.client_address[0] in ("127.0.0.1", "::1", "localhost")

    def _host_ok(self):
        host = (self.headers.get("Host") or "").rsplit(":", 1)[0].strip("[]")
        return host.lower() in self.allowed_hosts

    def _origin_ok(self):
        origin = (self.headers.get("Origin") or "").lower().rstrip("/")
        site = (self.headers.get("Sec-Fetch-Site") or "").lower()
        if origin:
            # Any request that declares an Origin must name THIS endpoint.
            # A page on another port of the same host is also refused here,
            # even though a plain navigation from it is harmless.
            return origin in self.allowed_origins
        # A navigation has no Origin. same-site covers a link from the main
        # terminal (port 7431 -> 7433); cross-site covers a foreign page.
        if site and site not in ("same-origin", "same-site", "none"):
            return False
        return True

    def _guard(self):
        return self._peer_ok() and self._host_ok() and self._origin_ok()

    def _send(self, code, ctype, body, extra=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "same-origin")
        # Deliberately NO Access-Control-Allow-* headers: a foreign page can
        # never read a response even if it manages to send a request.
        if extra:
            for k, v in extra:
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, obj, code=200, extra=None):
        self._send(code, "application/json; charset=utf-8",
                   _json_bytes(obj), extra)

    def _cookie(self, name):
        raw = self.headers.get("Cookie") or ""
        for part in raw.split(";"):
            k, _, v = part.strip().partition("=")
            if k == name:
                return v
        return ""

    def _authed(self, strict=True):
        if not (self._guard()
                and self.vault.session_ok(self._cookie(SESSION_COOKIE))):
            return False
        if not strict:
            return True
        return hmac.compare_digest(self.headers.get(CSRF_HEADER) or "", "1")

    def _session_cookie(self):
        return ("%s=%s; HttpOnly; SameSite=Strict; Path=/"
                % (SESSION_COOKIE, self.vault.issue_session()))

    def _body(self):
        try:
            n = int(self.headers.get("Content-Length", "0") or "0")
            if n > 256 * 1024:
                return {}
            raw = self.rfile.read(n) if n else b""
            return json.loads(raw.decode("utf-8")) if raw else {}
        except Exception:
            return {}

    def do_GET(self):
        if not self._guard():
            return self._send(403, "text/plain; charset=utf-8", b"host only")
        path = (self.path or "").split("?")[0]
        cookie = [("Set-Cookie", self._session_cookie())]
        if path in ("/", "/audit.html", "/index.html"):
            try:
                with open(self.page_file, "rb") as f:
                    page = f.read()
            except OSError:
                return self._send(500, "text/plain; charset=utf-8", b"page missing")
            return self._send(200, "text/html; charset=utf-8", page, cookie)
        if path == "/vidland-i18n.js":
            try:
                with open(self.lexicon_file, "rb") as f:
                    js = f.read()
            except OSError:
                return self._send(500, "text/plain; charset=utf-8", b"lexicon missing")
            return self._send(200, "application/javascript; charset=utf-8", js, cookie)
        if path == "/api/audit/ping":
            return self._json({
                "ok": True, "authed": self._authed(),
                "proof": {
                    "peer": self.client_address[0],
                    "host": self.headers.get("Host") or "",
                    "origin": self.headers.get("Origin") or "(same origin)",
                    "site": self.headers.get("Sec-Fetch-Site") or "(none)",
                    "session": self.vault.session_ok(self._cookie(SESSION_COOKIE)),
                    "keyMode": KEY_MODE,
                    "auth": "host-proof/no-passphrase"}}, 200, cookie)
        if path == "/api/audit/data":
            if not self._authed(False):
                return self._json({"error": "UNAUTHORISED"}, 401)
            return self._json(self.vault.data_view())
        return self._send(404, "text/plain; charset=utf-8", b"not found")

    def do_POST(self):
        if not self._guard():
            return self._send(403, "text/plain; charset=utf-8", b"host only")
        if not self._authed():
            return self._json({"error": "UNAUTHORISED"}, 401)
        path = (self.path or "").split("?")[0]
        body = self._body()
        if path == "/api/audit/approve":
            return self._json(self.vault.approve(body.get("requestId", ""),
                                                 body.get("policy")))
        if path == "/api/audit/deny":
            return self._json(self.vault.deny(body.get("requestId", ""),
                                              body.get("note", "")))
        if path == "/api/audit/revoke":
            return self._json(self.vault.revoke(body))
        if path == "/api/audit/device":
            return self._json(self.vault.set_device(body.get("device", ""),
                                                    body.get("patch")))
        if path == "/api/audit/policy":
            return self._json(self.vault.set_default_policy(body.get("patch")))
        if path == "/api/audit/purge":
            return self._json(self.vault.purge_all())
        return self._json({"error": "NOT_FOUND"}, 404)

    def do_OPTIONS(self):
        """Never answer a CORS preflight. A foreign page trying to POST with
        X-VDL-Audit cannot proceed, because the browser gets no ACAO header."""
        self._send(403, "text/plain; charset=utf-8", b"cross-origin refused")

    def do_PUT(self):
        return self.do_OPTIONS()

    def do_DELETE(self):
        return self.do_OPTIONS()


def rotate_master():
    """Replace the exposed Chancellery key pair with a fresh RSA-2048 pair.

    The old private key was inlined in admin.html in git history, so treat it
    as public. This command:
      * backs up the current DPAPI-sealed private key to master.key.old
        (still encrypted, so historical envelopes remain recoverable),
      * writes a brand new DPAPI-sealed private key to master.key,
      * rewrites PUBLIC_JWK in vidland-core.js to the matching public key.

    Envelopes sealed with the OLD public key can no longer be opened by the
    running server; restore master.key.old (and the old PUBLIC_JWK) to read
    them. Newly submitted applications use the new pair immediately.
    """
    import shutil
    if not CRYPTO_OK:
        raise RuntimeError("PyCryptodome is required to rotate the key")
    key = RSA.generate(2048)
    n = key.n
    e = key.e

    def b64u_int(i):
        raw = i.to_bytes((i.bit_length() + 7) // 8, "big")
        return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")

    core = os.path.join(ROOT, "vidland-core.js")
    with open(core, "r", encoding="utf-8") as f:
        txt = f.read()
    block = ('var PUBLIC_JWK = {\n'
             '    kty: "RSA",\n'
             '    n: "%s",\n'
             '    e: "%s"\n'
             '  };' % (b64u_int(n), b64u_int(e)))
    txt2, count = re.subn(r"var\s+PUBLIC_JWK\s*=\s*\{.*?\}\s*;",
                          block, txt, count=1, flags=re.S)
    if count != 1:
        raise RuntimeError("vidland-core.js 中未找到 PUBLIC_JWK，未做任何改动")
    if os.path.isfile(MASTER_KEY_FILE):
        shutil.copy2(MASTER_KEY_FILE, MASTER_KEY_FILE + ".old")
    with open(core, "w", encoding="utf-8", newline="\n") as f:
        f.write(txt2)
    _atomic_write(MASTER_KEY_FILE, dpapi_protect(key.export_key(format="PEM")))
    print("  已生成新的 Chancellery RSA-2048 密钥对。", flush=True)
    print("  新公钥已写入 vidland-core.js，新私钥已 DPAPI 封装到 master.key。",
          flush=True)
    print("  旧私钥加密备份: %s" % (MASTER_KEY_FILE + ".old"), flush=True)
    print("  注意: 旧公钥密封的历史信封需用备份私钥才能打开；"
          "请刷新所有终端页面以加载新公钥。", flush=True)


VAULT = None


def init(port):
    global VAULT
    if VAULT is None:
        VAULT = AuditVault()
    AuditHandler.vault = VAULT
    AuditHandler.page_file = os.path.join(ROOT, "audit.html")
    AuditHandler.lexicon_file = os.path.join(ROOT, "vidland-i18n.js")
    AuditHandler.allowed_hosts = frozenset({"127.0.0.1", "localhost", "::1"})
    AuditHandler.allowed_origins = frozenset({
        "http://127.0.0.1:%d" % port,
        "http://localhost:%d" % port,
        "http://[::1]:%d" % port})
    return VAULT


def start_audit_server(port):
    """Bind loopback ONLY — unlike the CA enrolment port, this one must
    never be reachable from the LAN at the socket level."""
    vault = init(port)
    try:
        srv = http.server.ThreadingHTTPServer(("127.0.0.1", port), AuditHandler)
    except OSError as exc:
        print("  [audit] 审计端口 %d 不可用: %s" % (port, exc), flush=True)
        return vault, None
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True,
                     name="vdl-audit-host").start()
    return vault, srv


if __name__ == "__main__":
    import sys
    if "--rotate" in sys.argv:
        rotate_master()
    elif "--info" in sys.argv:
        print("key mode      :", KEY_MODE)
        print("crypto        :", CRYPTO_OK)
        print("authentication: no passphrase (loopback + Host/Origin proof + signed session)")
        print("master.key    :", os.path.isfile(MASTER_KEY_FILE))
        print("audit vault   :", os.path.isfile(VAULT_FILE))
    else:
        print("用法: python audit_vault.py --rotate | --info")
