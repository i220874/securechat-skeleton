"""
scripts/gen_ca.py
Generate a self-signed root CA private key and certificate.
Usage:
  python3 scripts/gen_ca.py --name "My Root CA" --out certs/ca
This writes:
  certs/ca.key.pem
  certs/ca.cert.pem
File permissions: private key written with 0o600.
"""
import argparse
import os
import datetime
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID

def main():
    p = argparse.ArgumentParser()
    p.add_argument('--name', required=True, help='CA common name (e.g. "FAST-NU Root CA")')
    p.add_argument('--out', required=True, help='Output path prefix (e.g. certs/ca)')
    p.add_argument('--days', type=int, default=3650, help='Validity days (default 10 years)')
    args = p.parse_args()

    key_path = args.out + '.key.pem'
    cert_path = args.out + '.cert.pem'

    # generate RSA key
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    # Subject and issuer are the same (self-signed)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, args.name),
    ])

    now = datetime.datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=args.days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(private_key=key, algorithm=hashes.SHA256())
    )

    # write private key (PEM)
    with open(key_path, 'wb') as f:
        f.write(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
    os.chmod(key_path, 0o600)

    # write cert (PEM)
    with open(cert_path, 'wb') as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print(f"CA key -> {key_path}")
    print(f"CA cert -> {cert_path}")

if __name__ == '__main__':
    main()
