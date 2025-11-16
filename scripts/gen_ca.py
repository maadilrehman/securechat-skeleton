#!/usr/bin/env python3
"""
gen_ca.py
---------
Generate a Root Certificate Authority (CA):
 - RSA private key (ca.key.pem)
 - Self-signed X.509 certificate (ca.cert.pem)

Usage:
  python gen_ca.py --out-dir certs --cn "FAST-NU Root CA" --days 3650

 NEVER commit the generated private key to Git!
"""

import argparse
import os
from datetime import datetime, timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def gen_ca(out_dir: str, cn: str, days: int):
    os.makedirs(out_dir, exist_ok=True)

    # 1. Create RSA private key
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"PK"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"FAST-NUCES"),
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])

    now = datetime.utcnow()

    # 2. Self-signed certificate
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=days))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True
        )
        .sign(key, hashes.SHA256())
    )

    # 3. Write key & cert
    key_path = os.path.join(out_dir, "ca.key.pem")
    cert_path = os.path.join(out_dir, "ca.cert.pem")

    with open(key_path, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print(f"[+] Root CA key written to:   {key_path}")
    print(f"[+] Root CA cert written to:  {cert_path}")
    print("[✓] Root CA generation complete.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate a Root Certificate Authority (CA)")
    parser.add_argument("--out-dir", default="certs", help="Directory to write CA files")
    parser.add_argument("--cn", default="SecureChat Root CA", help="Common Name")
    parser.add_argument("--days", type=int, default=3650, help="Validity (days)")
    args = parser.parse_args()

    gen_ca(args.out_dir, args.cn, args.days)
