#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Generate / renew the local CA and its CA-signed TLS certificate.

    python make_cert.py            # renew only when needed (idempotent)
    python make_cert.py --status   # report expiry, change nothing
    python make_cert.py --force    # reissue server cert, KEEP the CA
    python make_cert.py --new-ca   # regenerate the CA too (phones must reinstall)

    VDL_LAN_IP=192.168.3.31 python make_cert.py
    VDL_LAN_DNS=vidland.example.com python make_cert.py

Why "keep the CA": phones trust the root CA for 10 years. Renewing the
short-lived server certificate under the SAME CA needs no action on any
phone. Rebuilding the CA is what forces every device to reinstall it.

All outputs go to vidland-data/ (git-ignored). Needs OpenSSL; it is found
on PATH or in the usual Windows install locations, or set VDL_OPENSSL to
an explicit executable path.
"""
import datetime
import glob
import os
import shutil
import socket
import ssl
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
OUT = ROOT / "vidland-data"
CA_KEY = OUT / "ca-key.pem"
CA_CERT = OUT / "ca.pem"
SRV_KEY = OUT / "lan-key.pem"
SRV_CERT = OUT / "lan-cert.pem"
CSR = OUT / "_server.csr"
EXT = OUT / "_server.ext"

DAYS_CA = 3650
DAYS_SRV = 365          # iOS/Safari reject server certs valid over 398 days
RENEW_BELOW = 30        # auto-renew when fewer than 30 days remain
QUIET = "--quiet" in sys.argv


def say(msg):
    if not QUIET:
        print(msg)


def find_openssl():
    """PATH first, then the usual Windows install locations. A GUI/double
    click launch has a much smaller PATH than an interactive shell, so
    relying on PATH alone makes certificate generation fail mysteriously."""
    override = os.environ.get("VDL_OPENSSL", "").strip().strip('"')
    if override:
        return override if os.path.isfile(override) else None
    found = shutil.which("openssl")
    if found:
        return found
    pats = [
        r"C:\Program Files\Git\usr\bin\openssl.exe",
        r"C:\Program Files (x86)\Git\usr\bin\openssl.exe",
        r"C:\Program Files\OpenSSL-Win*\bin\openssl.exe",
        r"C:\Program Files (x86)\OpenSSL-Win*\bin\openssl.exe",
        os.path.expandvars(r"%LOCALAPPDATA%\Programs\Git\usr\bin\openssl.exe"),
        os.path.expandvars(r"%USERPROFILE%\.workbuddy\binaries\PortableGit\versions\*\usr\bin\openssl.EXE"),
        r"E:\安装\WorkBuddy\resources\vendor\PortableGit\usr\bin\openssl.EXE",
    ]
    for pat in pats:
        for hit in sorted(glob.glob(pat), reverse=True):
            if os.path.isfile(hit):
                return hit
    return None


OPENSSL = find_openssl()


def openssl_missing_hint():
    return ("找不到 OpenSSL，无法生成局域网所需的 TLS 证书。\n"
            "  解决办法（任选其一）：\n"
            "    1) 安装 Git for Windows（自带 openssl.exe），然后重新运行；\n"
            "    2) 把 openssl.exe 所在目录加入 PATH 后重新运行；\n"
            "    3) 用环境变量直接指定：VDL_OPENSSL=C:\\path\\to\\openssl.exe\n"
            "  另可手动执行：python make_cert.py 查看详细输出。")


def run(args):
    r = subprocess.run([OPENSSL] + args, capture_output=True, text=True,
                       encoding="utf-8", errors="replace")
    if r.returncode != 0:
        raise RuntimeError("openssl %s failed:\n%s" % (" ".join(args[:2]), r.stderr.strip()))
    return r


def cert_days_left(path):
    """Days until expiry, or None if the certificate is missing/unreadable."""
    if not path.is_file():
        return None
    try:
        d = ssl._ssl._test_decode_cert(str(path))
        end = datetime.datetime.strptime(d["notAfter"], "%b %d %H:%M:%S %Y %Z")
        return (end - datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)).days
    except Exception:
        return None


def cert_san_ips(path):
    try:
        d = ssl._ssl._test_decode_cert(str(path))
        return {v for kind, v in d.get("subjectAltName", ()) if kind == "IP Address"}
    except Exception:
        return set()


def lan_ips():
    ips = set()
    override = os.environ.get("VDL_LAN_IP", "").strip()
    if override:
        ips.update(x.strip() for x in override.split(",") if x.strip())
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ips.add(info[4][0])
    except Exception:
        pass
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("223.5.5.5", 80))
        ips.add(s.getsockname()[0])
        s.close()
    except Exception:
        pass
    return {a for a in ips if not a.startswith("127.")}


def status():
    ca = cert_days_left(CA_CERT)
    srv = cert_days_left(SRV_CERT)
    print("  Root CA      %s" % ("expired/missing" if ca is None else "%d 天 (%s)" % (
        ca, "需要重建 CA" if ca <= 0 else "无需手机操作")))
    print("  服务器证书   %s" % ("expired/missing" if srv is None else "%d 天 (%s)" % (
        srv, "即将自动续期" if srv < RENEW_BELOW else "正常")))
    cur_ips = sorted(lan_ips())
    san_ips = sorted(cert_san_ips(SRV_CERT))
    print("  当前 IP      %s" % (", ".join(cur_ips) or "(未探测到)"))
    print("  证书 SAN IP  %s" % (", ".join(san_ips) or "(无)"))
    missing = set(cur_ips) - set(san_ips)
    if missing:
        print("  新 IP 未覆盖: %s → 运行时会自动重签（CA 不变）" % ", ".join(sorted(missing)))
    return 0


def ensure_ca(new_ca):
    if new_ca or not (CA_KEY.is_file() and CA_CERT.is_file()):
        run(["req", "-x509", "-newkey", "rsa:2048", "-sha256", "-nodes",
             "-days", str(DAYS_CA), "-keyout", str(CA_KEY), "-out", str(CA_CERT),
             "-subj", "/CN=Vidland Local Root CA",
             "-addext", "basicConstraints=critical,CA:TRUE",
             "-addext", "keyUsage=critical,keyCertSign,cRLSign"])
        say("  CA 已生成: %s" % CA_CERT)
        if new_ca:
            print("  ⚠ CA 已重建，所有手机必须重新安装根证书。")
        return True
    return False


def issue_server_cert():
    ips = lan_ips()
    san = ["DNS:localhost", "IP:127.0.0.1"] + ["IP:" + a for a in sorted(ips)]
    dns = os.environ.get("VDL_LAN_DNS", "").strip()
    if dns:
        san += ["DNS:" + x.strip() for x in dns.split(",") if x.strip()]
    EXT.write_text(
        "basicConstraints=CA:FALSE\n"
        "keyUsage=digitalSignature,keyEncipherment\n"
        "extendedKeyUsage=serverAuth\n"
        "subjectAltName=" + ",".join(san) + "\n",
        encoding="ascii")
    try:
        run(["req", "-newkey", "rsa:2048", "-sha256", "-nodes",
             "-keyout", str(SRV_KEY), "-out", str(CSR),
             "-subj", "/CN=Vidland-LAN"])
        run(["x509", "-req", "-in", str(CSR), "-CA", str(CA_CERT),
             "-CAkey", str(CA_KEY), "-CAcreateserial", "-out", str(SRV_CERT),
             "-days", str(DAYS_SRV), "-sha256", "-extfile", str(EXT)])
    finally:
        for p in (CSR, EXT, OUT / "ca.srl"):
            try:
                p.unlink()
            except OSError:
                pass
    say("  服务器证书已签发（复用现有 CA，手机无需操作）")
    say("  有效期 %d 天 · SAN: %s" % (DAYS_SRV, ", ".join(san)))
    return True


def main():
    if OPENSSL is None:
        # stderr, so a caller capturing only stderr still sees the real cause.
        print(openssl_missing_hint(), file=sys.stderr)
        return 1
    OUT.mkdir(exist_ok=True)

    if "--status" in sys.argv:
        return status()

    force = "--force" in sys.argv
    new_ca = "--new-ca" in sys.argv
    try:
        ca_rebuilt = ensure_ca(new_ca)
    except RuntimeError as exc:
        print("证书生成失败：%s" % exc, file=sys.stderr)
        print(openssl_missing_hint(), file=sys.stderr)
        return 1

    left = cert_days_left(SRV_CERT)
    missing_ips = lan_ips() - cert_san_ips(SRV_CERT)
    need = (force or ca_rebuilt or left is None or left < RENEW_BELOW or bool(missing_ips))

    if not need:
        say("  证书有效（剩余 %d 天），IP 未变化，无需操作。" % left)
        return 0

    if left is not None and left < RENEW_BELOW:
        say("  服务器证书剩余 %d 天，自动续期…" % left)
    if missing_ips:
        say("  检测到新 IP %s，自动重签…" % ", ".join(sorted(missing_ips)))
    try:
        issue_server_cert()
    except RuntimeError as exc:
        print("证书签发失败：%s" % exc, file=sys.stderr)
        print(openssl_missing_hint(), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
