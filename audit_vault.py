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
STORE_FILE = os.path.join(DATA_DIR, "store.json")
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


# --------------------------------------------------------------------------
# Chancellery master key ring
# --------------------------------------------------------------------------
# master.key used to hold one DPAPI-sealed PEM. It now holds a DPAPI-sealed
# key ring: {"v":2,"active":<kid>,"keys":[{kid,pem,createdAt}]}. A legacy
# PEM file is still accepted and treated as a one-generation ring in memory,
# so an existing installation keeps working without any rewrite.
MASTER_RING_V = 2
KID_DOMAIN = b"VDL-MASTER-v1|"


def master_kid(n, e):
    """Stable 16-hex fingerprint of an RSA public key (modulus || exponent)."""
    nb = n.to_bytes((n.bit_length() + 7) // 8, "big")
    eb = e.to_bytes((e.bit_length() + 7) // 8, "big")
    return hashlib.sha256(KID_DOMAIN + nb + eb).hexdigest()[:16]


def key_kid(key):
    return master_kid(key.n, key.e)


def load_master_ring(path=None):
    p = path or MASTER_KEY_FILE
    if not os.path.isfile(p):
        return None
    with open(p, "rb") as f:
        raw = dpapi_unprotect(f.read())
    if raw.lstrip().startswith(b"{"):
        ring = json.loads(raw.decode("utf-8"))
        if ring.get("v") != MASTER_RING_V or not ring.get("keys"):
            raise ValueError("master.key 密钥环版本不支持")
        return ring
    # Legacy single-PEM format. Compute its kid from the public half so a
    # sealed envelope produced after this change can still be routed to it.
    key = RSA.import_key(raw) if CRYPTO_OK else None
    kid = key_kid(key) if key else "legacy"
    return {"v": MASTER_RING_V, "active": kid,
            "keys": [{"kid": kid, "pem": raw.decode("utf-8", "replace"),
                      "createdAt": 0}]}


def save_master_ring(ring, path=None):
    _atomic_write(path or MASTER_KEY_FILE, dpapi_protect(_json_bytes(ring)))


def ring_active_pem(ring):
    kid = ring.get("active")
    for item in ring.get("keys", []):
        if item.get("kid") == kid:
            return item.get("pem", "")
    return ring["keys"][-1].get("pem", "")


def ring_pem_for(ring, kid):
    """Fall back to the active key for old envelopes that carry no kid."""
    for item in ring.get("keys", []):
        if item.get("kid") == kid:
            return item.get("pem")
    return ring_active_pem(ring)


def public_jwk_from_core(path=None):
    """Return (n, e, PUBLIC_KID literal, whole file text)."""
    p = path or os.path.join(ROOT, "vidland-core.js")
    with open(p, "r", encoding="utf-8") as f:
        txt = f.read()
    m = re.search(r"var\s+PUBLIC_JWK\s*=\s*\{.*?\}\s*;", txt, re.S)
    if not m:
        return None, None, None, txt
    blk = m.group(0)
    nm = re.search(r"\bn:\s*\"([^\"]+)\"", blk)
    em = re.search(r"\be:\s*\"([^\"]+)\"", blk)
    km = re.search(r"var\s+PUBLIC_KID\s*=\s*\"([^\"]+)\"", txt)
    n = int.from_bytes(_b64u(nm.group(1)), "big") if nm else None
    e = int.from_bytes(_b64u(em.group(1)), "big") if em else None
    return n, e, (km.group(1) if km else None), txt


def _seal_hybrid(pub, obj, kid):
    """Re-seal a plaintext business object. Mirrors sealForChancellery() in
    vidland-core.js: WebCrypto returns ciphertext||tag in `ct`."""
    raw = secrets.token_bytes(32)
    iv = secrets.token_bytes(12)
    c = AES.new(raw, AES.MODE_GCM, nonce=iv, mac_len=16)
    body, tag = c.encrypt_and_digest(_json_bytes(obj))
    ek = PKCS1_OAEP.new(pub, hashAlgo=SHA256).encrypt(raw)
    b64 = lambda b: base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")
    return {"v": 1, "kid": kid,
            "alg": "RSA-OAEP-2048/SHA256 + AES-256-GCM",
            "ek": b64(ek), "iv": b64(iv), "ct": b64(body + tag)}


def _open_hybrid(pem, env):
    key = RSA.import_key(pem)
    raw = PKCS1_OAEP.new(key, hashAlgo=SHA256).decrypt(_b64u(env["ek"]))
    ct = _b64u(env["ct"])
    c = AES.new(raw, AES.MODE_GCM, nonce=_b64u(env["iv"]), mac_len=16)
    return json.loads(c.decrypt_and_verify(ct[:-16], ct[-16:]).decode("utf-8"))


def service_port_in_use():
    """A rotation must never race a live server: it holds the old private key
    in memory while new pages would start sealing with the new public key."""
    import socket
    port = int(os.environ.get("VDL_PORT", "7431"))
    s = socket.socket()
    s.settimeout(0.35)
    try:
        return s.connect_ex(("127.0.0.1", port)) == 0
    finally:
        s.close()


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
        self.master_ring = None
        self._rsa_kid = None
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
            n, e, _kid, _txt = public_jwk_from_core()
            return (n, e) if n is not None and e is not None else None
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
        ring = load_master_ring()
        if ring:
            self.master_ring = ring
            pem = ring_active_pem(ring)
            if not pem:
                raise RuntimeError("master.key 密钥环中没有可用私钥")
            return pem.encode("utf-8") if isinstance(pem, str) else pem
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
            kid = key_kid(key)
            self.master_ring = {"v": MASTER_RING_V, "active": kid,
                                "keys": [{"kid": kid,
                                          "pem": pem.decode("utf-8"),
                                          "createdAt": _now()}]}
            save_master_ring(self.master_ring)
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
            n, e, kid, _txt = public_jwk_from_core()
            if n is not None and (key.n, key.e) != (n, e):
                print("  [audit] 警告: master.key 与 core.js 的 PUBLIC_JWK "
                      "不一致，新提交的密封详情将无法解开。", flush=True)
                return
            active = (self.master_ring or {}).get("active")
            if kid and active and kid != active:
                print("  [audit] 警告: core.js 的 PUBLIC_KID 与 master.key "
                      "活动密钥代不一致，请核对或执行一次 --verify。", flush=True)
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
        this process; the caller receives only plaintext JSON. Envelopes
        carrying a `kid` are routed to that generation of the key ring, so a
        rotation never makes an older record unreadable."""
        if not CRYPTO_OK:
            raise RuntimeError("PyCryptodome is required for /api/vault/open")
        kid = env.get("kid") or (self.master_ring or {}).get("active")
        pem = (ring_pem_for(self.master_ring, kid) if self.master_ring
               else self.master_pem)
        if not pem:
            raise RuntimeError("NO_PRIVATE_KEY_FOR_KID: %s" % kid)
        if isinstance(pem, str):
            pem = pem.encode("utf-8")
        if self._rsa_key is None or self._rsa_kid != kid:
            self._rsa_key = RSA.import_key(pem)
            self._rsa_kid = kid
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


def rotate_master(keep_old=False, allow_running=False):
    """Rotate the Chancellery key pair WITHOUT orphaning historical records.

    The old implementation swapped PUBLIC_JWK and kept the retired private
    key forever in master.key.old, because every existing `vdl.v1.env.*`
    envelope was still sealed to the old public key. That meant a rotation
    never actually retired anything: one more private key had to be guarded,
    the leaked key from git history stayed useful, and older applications in
    the Authority failed to decrypt.

    This version:
      1. refuses to run while the server is up (it holds the old key in RAM);
      2. re-seals EVERY historical envelope from the old private key to the
         new public key, in memory, before publishing the new key;
      3. writes a versioned key ring, the migrated register and the new
         PUBLIC_JWK / PUBLIC_KID atomically, with a full rollback on any
         verification failure;
      4. deletes master.key.old once the migration is verified, so the old
         key is genuinely gone from this machine (pass --keep-old to retain
         it for an out-of-band archive).

    Plaintext business data exists only inside this process during the
    migration and is never written to disk unencrypted.
    """
    if not CRYPTO_OK:
        raise RuntimeError("PyCryptodome is required to rotate the key")
    if not allow_running and service_port_in_use():
        raise RuntimeError(
            "检测到政务服务仍在运行。请先停止服务再轮换"
            "（python quickstart.py stop），否则服务端仍持有旧私钥，"
            "而新页面已经开始用新公钥加密。")

    core_path = os.path.join(ROOT, "vidland-core.js")
    ring = load_master_ring()
    if not ring:
        raise RuntimeError("找不到 master.key。请先启动一次服务完成主私钥迁移。")

    # Exact original bytes, so any failure can restore all three files.
    with open(MASTER_KEY_FILE, "rb") as f:
        master_before = f.read()
    with open(core_path, "rb") as f:
        core_before = f.read()
    store_before = None
    if os.path.isfile(STORE_FILE):
        with open(STORE_FILE, "rb") as f:
            store_before = f.read()

    n_e = public_jwk_from_core(core_path)
    if n_e[0] is None:
        raise RuntimeError("vidland-core.js 中未找到 PUBLIC_JWK，未做任何改动")
    core_text = n_e[3]

    old_key = RSA.import_key(ring_active_pem(ring))
    old_kid = key_kid(old_key)
    new_key = RSA.generate(2048)
    new_kid = key_kid(new_key)

    def b64u_int(i):
        raw = i.to_bytes((i.bit_length() + 7) // 8, "big")
        return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")

    # ---- 1. Re-seal every stored envelope -------------------------------
    store = (json.loads(store_before.decode("utf-8")) if store_before
             else {"rev": 0, "data": {}})
    data = store.get("data", {})
    if not isinstance(data, dict):
        raise RuntimeError("store.json 结构异常（data 不是对象），未做任何改动")
    migrated, proof = 0, []
    for k in list(data.keys()):
        if not k.startswith("vdl.v1.env."):
            continue
        try:
            env = json.loads(data[k])
            payload = env.get("payload") or {}
            if not payload.get("ek"):
                continue
            pem = ring_pem_for(ring, payload.get("kid") or old_kid)
            plain = _open_hybrid(pem, payload)
            env["payload"] = _seal_hybrid(new_key.publickey(), plain, new_kid)
            data[k] = json.dumps(env, ensure_ascii=False)
            proof.append((k, env["payload"], plain))
            migrated += 1
        except Exception as exc:
            raise RuntimeError("信封 %s 迁移失败，未做任何改动：%s" % (k, exc))

    # ---- 2. Publish the new generation ----------------------------------
    new_ring = {"v": MASTER_RING_V, "active": new_kid,
                "keys": [{"kid": new_kid,
                          "pem": new_key.export_key(format="PEM").decode("ascii"),
                          "createdAt": _now()}]}
    block = ('var PUBLIC_JWK = {\n'
             '    kty: "RSA",\n'
             '    n: "%s",\n'
             '    e: "%s"\n'
             '  };' % (b64u_int(new_key.n), b64u_int(new_key.e)))
    txt2, count = re.subn(r"var\s+PUBLIC_JWK\s*=\s*\{.*?\}\s*;",
                          lambda m: block, core_text, count=1, flags=re.S)
    if count != 1:
        raise RuntimeError("vidland-core.js 中未找到 PUBLIC_JWK，未做任何改动")
    kid_line = '  var PUBLIC_KID = "%s";' % new_kid
    if re.search(r"var\s+PUBLIC_KID\s*=\s*\"[^\"]+\"\s*;", txt2):
        txt2 = re.sub(r"var\s+PUBLIC_KID\s*=\s*\"[^\"]+\"\s*;",
                      lambda m: kid_line, txt2, count=1)
    else:
        txt2 = txt2.replace(block, block + "\n" + kid_line, 1)

    def rollback(cause):
        _atomic_write(MASTER_KEY_FILE, master_before)
        if store_before is None:
            if os.path.isfile(STORE_FILE):
                os.remove(STORE_FILE)
        else:
            _atomic_write(STORE_FILE, store_before)
        _atomic_write(core_path, core_before)
        raise RuntimeError("轮换校验失败，已回滚到原状态：%s" % cause)

    try:
        save_master_ring(new_ring)
        if store_before is not None:
            store["data"] = data
            store["rev"] = int(store.get("rev", 0)) + 1
            _atomic_write(STORE_FILE,
                          json.dumps(store, ensure_ascii=False).encode("utf-8"))
        _atomic_write(core_path, txt2.encode("utf-8"))
    except Exception as exc:
        rollback(str(exc))

    # ---- 3. Verify before destroying the old generation ------------------
    try:
        check_ring = load_master_ring()
        check_pem = ring_active_pem(check_ring)
        for key, payload, plain in proof:
            if _open_hybrid(check_pem, payload) != plain:
                raise RuntimeError("信封 %s 重封后明文不一致" % key)
        cn, ce, ck, _ = public_jwk_from_core(core_path)
        if (cn, ce) != (new_key.n, new_key.e) or ck != new_kid:
            raise RuntimeError("core.js 公钥与 master.key 不一致")
    except Exception as exc:
        rollback(str(exc))

    # ---- 4. The retired key is now useless here: destroy the backup -----
    old_backup = MASTER_KEY_FILE + ".old"
    destroyed = False
    if not keep_old and os.path.isfile(old_backup):
        os.remove(old_backup)
        destroyed = True

    print("  已生成新的 Chancellery RSA-2048 密钥对。", flush=True)
    print("  密钥代: %s -> %s" % (old_kid, new_kid), flush=True)
    print("  已重封历史密封信封: %d 份，全部校验通过。" % migrated, flush=True)
    print("  新公钥 / kid 已写入 vidland-core.js；新私钥只保留在 "
          "DPAPI 封装的 master.key 密钥环中。", flush=True)
    if destroyed:
        print("  已删除旧私钥备份 master.key.old（当前登记册不再需要它）。",
              flush=True)
    elif os.path.isfile(old_backup):
        print("  按 --keep-old 保留了 master.key.old；请自行离线保管或销毁。",
              flush=True)
    print("  请重启服务并刷新所有终端页面；旧页面缓存的公钥会在刷新后更新。",
          flush=True)
    return {"oldKid": old_kid, "newKid": new_kid,
            "migrated": migrated, "oldBackupDestroyed": destroyed}


def verify_envelopes():
    """Read-only health check: does the shipped public key match the key ring,
    and can every stored envelope still be opened?"""
    ring = load_master_ring()
    if not ring:
        return {"ok": False, "error": "master.key 不存在"}
    active = ring.get("active")
    n, e, core_kid, _txt = public_jwk_from_core()
    core_matches = (n is not None and master_kid(n, e) == active
                    and (core_kid is None or core_kid == active))
    total = opened = stale = 0
    failed = []
    if os.path.isfile(STORE_FILE):
        with open(STORE_FILE, "r", encoding="utf-8") as f:
            reg = json.load(f)
        for k, v in (reg.get("data") or {}).items():
            if not k.startswith("vdl.v1.env."):
                continue
            total += 1
            try:
                env = json.loads(v)
                payload = env.get("payload") or {}
                if not payload.get("ek"):
                    continue
                _open_hybrid(ring_pem_for(ring, payload.get("kid")), payload)
                opened += 1
                if payload.get("kid") and payload["kid"] != active:
                    stale += 1
            except Exception as exc:
                failed.append({"key": k, "error": str(exc)[:140]})
    return {"ok": core_matches and not failed,
            "activeKid": active, "coreKid": core_kid,
            "coreMatches": core_matches,
            "generations": len(ring.get("keys", [])),
            "envelopes": total, "opened": opened, "stale": stale,
            "failed": failed,
            "legacyBackup": os.path.isfile(MASTER_KEY_FILE + ".old")}


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
        rotate_master(keep_old="--keep-old" in sys.argv)
    elif "--verify" in sys.argv:
        r = verify_envelopes()
        for k in ("ok", "activeKid", "coreKid", "coreMatches", "generations",
                  "envelopes", "opened", "stale", "legacyBackup"):
            print("%-14s: %s" % (k, r.get(k)))
        if r.get("failed"):
            print("failed        :", r["failed"])
        print("结果          :", "全部可解" if r["ok"] else "存在问题")
        sys.exit(0 if r["ok"] else 1)
    elif "--info" in sys.argv:
        r = verify_envelopes()
        print("key mode      :", KEY_MODE)
        print("crypto        :", CRYPTO_OK)
        print("authentication: no passphrase (loopback + Host/Origin proof + signed session)")
        print("master.key    :", os.path.isfile(MASTER_KEY_FILE))
        print("audit vault   :", os.path.isfile(VAULT_FILE))
        print("active kid    :", r.get("activeKid"))
        print("core.js kid   :", r.get("coreKid"))
        print("generations   :", r.get("generations"))
        print("envelopes     : %s (opened %s, stale %s)" %
              (r.get("envelopes"), r.get("opened"), r.get("stale")))
        print("legacy backup :", r.get("legacyBackup"))
        print("health        :", "OK" if r.get("ok") else
              r.get("error") or "run --verify for details")
    else:
        print("用法: python audit_vault.py --info | --verify | "
              "--rotate [--keep-old]")
