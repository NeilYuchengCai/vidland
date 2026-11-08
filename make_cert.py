#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Generate a local CA and a CA-signed TLS certificate for LAN access.

    python make_cert.py            # generate (or reuse) the CA + server cert
    python make_cert.py --force    # regenerate everything
    VDL_LAN_IP=192.168.3.31 python make_cert.py

All outputs go to vidland-data/ (git-ignored). Install ca.pem on each
phone once; the server certificate then needs no per-device exceptions.

Requires OpenSSL on PATH.
"""
import os
import shutil
import socket
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
DAYS_SRV = 365  # iOS/Safari reject server certs valid longer than 398 days


def run(args):
    r = subprocess.run(["openssl"] + args, capture_output=True, text=True,
                       encoding="utf-8", errors="replace")
    if r.returncode != 0:
        raise RuntimeError("openssl %s failed:\n%s" % (" ".join(args[:2]), r.stderr.strip()))
    return r


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
    return sorted(a for a in ips if not a.startswith("127."))


def main():
    force = "--force" in sys.argv
    if shutil.which("openssl") is None:
        print("OpenSSL not found on PATH. Install it or set PATH and retry.")
        return 1
    OUT.mkdir(exist_ok=True)

    if force or not (CA_KEY.is_file() and CA_CERT.is_file()):
        run(["req", "-x509", "-newkey", "rsa:2048", "-sha256", "-nodes",
             "-days", str(DAYS_CA), "-keyout", str(CA_KEY), "-out", str(CA_CERT),
             "-subj", "/CN=Vidland Local Root CA",
             "-addext", "basicConstraints=critical,CA:TRUE",
             "-addext", "keyUsage=critical,keyCertSign,cRLSign"])
        print("  CA created: %s" % CA_CERT)
    else:
        print("  CA reused:  %s" % CA_CERT)

    if not force and SRV_KEY.is_file() and SRV_CERT.is_file():
        print("  Server certificate reused (use --force to regenerate).")
        return 0

    ips = lan_ips()
    san = ["DNS:localhost", "IP:127.0.0.1"] + ["IP:" + a for a in ips]
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

    print("  Server certificate: %s" % SRV_CERT)
    print("  SAN: %s" % ", ".join(san))
    print("  Install %s on each phone, then run: VDL_LAN=1 python serve.py" % CA_CERT)
    return 0


if __name__ == "__main__":
    sys.exit(main())
