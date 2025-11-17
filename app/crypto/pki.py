"""
Certificate loading, inspection, and validation helpers.

Implements:
- load_certificate(pem_bytes)
- verify_certificate_chain(peer_cert, ca_cert)
- verify_hostname(peer_cert, expected_cn)
- cert_fingerprint_sha256(peer_cert)
"""

from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import padding
import datetime


# -------------------- CUSTOM ERRORS --------------------

class CertificateError(Exception):
    """Base class for certificate-related errors."""


class BadCertificateError(CertificateError):
    """Used when certificate fails validation."""


# -------------------- LOADING CERTS --------------------

def load_certificate(pem_bytes: bytes) -> x509.Certificate:
    """
    Load a PEM-encoded X.509 certificate into a cryptography object.
    """
    try:
        return x509.load_pem_x509_certificate(pem_bytes)
    except Exception as e:
        raise BadCertificateError(f"Invalid certificate PEM: {e}")


def load_certificate_from_file(path: str) -> x509.Certificate:
    """
    Load certificate directly from a file path.
    """
    with open(path, "rb") as f:
        return load_certificate(f.read())


# -------------------- CORE VALIDATION --------------------

def verify_certificate_chain(peer_cert: x509.Certificate, ca_cert: x509.Certificate):
    """
    Verify:
    - peer_cert is signed by ca_cert (issuer = ca subject)
    - signature is correct
    - certificate is within validity period
    """

    # 1. Check issuer
    if peer_cert.issuer != ca_cert.subject:
        raise BadCertificateError("BAD_CERT: Issuer mismatch (not signed by CA).")

    # 2. Verify signature
    try:
        ca_cert.public_key().verify(
            peer_cert.signature,
            peer_cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            peer_cert.signature_hash_algorithm,
        )
    except Exception as e:
        raise BadCertificateError(f"BAD_CERT: Signature verification failed: {e}")

    # 3. Check validity dates
    now = datetime.datetime.utcnow()
    if not (peer_cert.not_valid_before <= now <= peer_cert.not_valid_after):
        raise BadCertificateError("BAD_CERT: Certificate expired or not yet valid.")

def verify_hostname(peer_cert: x509.Certificate, expected_cn: str):
    """
    Verify that certificate's CN matches expected hostname/identity.
    """
    try:
        cn_attr = peer_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0]
        actual_cn = cn_attr.value
    except Exception:
        raise BadCertificateError("BAD_CERT: Certificate has no CN field.")

    if actual_cn != expected_cn:
        raise BadCertificateError(
            f"BAD_CERT: Hostname mismatch. Expected '{expected_cn}', got '{actual_cn}'."
        )


# -------------------- CERT INSPECTION UTILS --------------------

def cert_fingerprint_sha256(cert: x509.Certificate) -> str:
    """
    Returns SHA-256 fingerprint in hex.
    Useful for transcript logging (assignment requirement).
    """
    fp = cert.fingerprint(hashes.SHA256())
    return fp.hex()


def extract_cn(cert: x509.Certificate) -> str:
    """Return Common Name of certificate."""
    return cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
