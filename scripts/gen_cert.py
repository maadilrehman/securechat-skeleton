#!/usr/bin/env python3
"""
gen_cert.py
-----------
Generate a client/server RSA keypair and sign a certificate using the Root CA.

Usage (PowerShell-friendly):
  python scripts/gen_cert.py --out-dir certs `
        --ca-key certs/ca.key.pem `
        --ca-cert certs/ca.cert.pem `
        --cn server.local `
        --server

Outputs:
  certs/<cn>.key.pem
  certs/<cn>.cert.pem

NEVER commit private keys to Git!
"""

import argparse
import os
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def load_pem_key(path: str):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def load_pem_cert(path: str):
    with open(path, "rb") as f:
        return x509.load_pem_x509_certificate(f.read())


def gen_cert(out_dir: str, ca_key_path: str, ca_cert_path: str,
             cn: str, is_server: bool, days: int):

    os.makedirs(out_dir, exist_ok=True)

    ca_key = load_pem_key(ca_key_path)
    ca_cert = load_pem_cert(ca_cert_path)

    # Generate private key
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"PK"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"FAST-NUCES"),
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])

    now = datetime.now(timezone.utc)

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=days))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True
        )
    )

    # Add SAN for server certs
    if is_server:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.DNSName(cn),
            ]),
            critical=False
        )

    cert = builder.sign(
        private_key=ca_key,
        algorithm=hashes.SHA256()
    )

    # Write outputs
    key_path = os.path.join(out_dir, f"{cn}.key.pem")
    cert_path = os.path.join(out_dir, f"{cn}.cert.pem")

    with open(key_path, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print(f"[+] Key written:  {key_path}")
    print(f"[+] Cert written: {cert_path}")
    print("[✓] Certificate generation complete.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate a certificate signed by Root CA")
    parser.add_argument("--out-dir", default="certs")
    parser.add_argument("--ca-key", required=True)
    parser.add_argument("--ca-cert", required=True)
    parser.add_argument("--cn", required=True)
    parser.add_argument("--server", action="store_true")
    parser.add_argument("--days", type=int, default=365)
    args = parser.parse_args()

    gen_cert(
        args.out_dir,
        args.ca_key,
        args.ca_cert,
        args.cn,
        args.server,
        args.days
    )
