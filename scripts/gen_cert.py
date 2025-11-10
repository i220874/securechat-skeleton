
"""
scripts/gen_cert.py
Generate an RSA key pair and an X.509 certificate signed by the given CA.
Usage:
 python3 scripts/gen_cert.py --ca-key certs/ca.key.pem --ca-cert certs/ca.cert.pem --cn server.local --out certs/server
Outputs:
 certs/server.key.pem
 certs/server.cert.pem
"""
import argparse
import os
import datetime
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.serialization import load_pem_private_key

def load_pem_key(path, password=None):
    with open(path, 'rb') as f:
        data = f.read()
    return load_pem_private_key(data, password=password)

def main():
    p = argparse.ArgumentParser()
    p.add_argument('--ca-key', required=True)
    p.add_argument('--ca-cert', required=True)
    p.add_argument('--cn', required=True, help='Common Name for the cert (e.g., server.local)')
    p.add_argument('--out', required=True, help='Output prefix (e.g., certs/server)')
    p.add_argument('--days', type=int, default=365, help='Validity days (default 1 year)')
    args = p.parse_args()

    ca_key = load_pem_key(args.ca_key)
    with open(args.ca_cert, 'rb') as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())

    # generate entity key
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, args.cn),
    ])
    now = datetime.datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=args.days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(private_key=ca_key, algorithm=hashes.SHA256())
    )

    key_path = args.out + '.key.pem'
    cert_path = args.out + '.cert.pem'

    with open(key_path, 'wb') as f:
        f.write(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
        )
    os.chmod(key_path, 0o600)

    with open(cert_path, 'wb') as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print(f"Generated key: {key_path}")
    print(f"Generated cert: {cert_path}")

if __name__ == '__main__':
    main()
