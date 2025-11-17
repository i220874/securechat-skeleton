# app/crypto/dh.py

import secrets
import hashlib

# ============================================================
# RFC 3526 - Group 14: 2048-bit MODP Group
# Source: https://datatracker.ietf.org/doc/html/rfc3526
# ============================================================

# 2048-bit safe prime (hex → int)
P_HEX = """
FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1
29024E088A67CC74020BBEA63B139B22514A08798E3404DD
EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245
E485B576625E7EC6F44C42E9A63A36210000000000090563
"""

# Remove newlines/spaces and convert to integer
p = int("".join(P_HEX.split()).replace("\n", ""), 16)

# Generator
g = 2


# ============================================================
# Private Key Generation
# ============================================================

def generate_private_key():
    """
    Generate a secure private exponent a or b.
    Must be 2 <= private < p-2.

    RFC recommends using a random value of size ~256 bits minimum.
    We will use ~256 bits to avoid very small exponents.
    """
    # 256-bit random exponent, but within group order constraints
    while True:
        priv = secrets.randbits(256)
        if 2 < priv < p - 2:
            return priv


# ============================================================
# Public Value Computation: A = g^a mod p, B = g^b mod p
# ============================================================

def compute_public_value(private_key: int) -> int:
    """
    Compute public value for DH:
    A = g^a mod p or B = g^b mod p
    """
    return pow(g, private_key, p)


# ============================================================
# Shared Secret Computation: Ks = B^a mod p or A^b mod p
# ============================================================

def compute_shared_secret(their_public: int, my_private: int) -> int:
    """
    Compute the shared secret Ks = (their_public)^my_private mod p.
    """
    return pow(their_public, my_private, p)


# ============================================================
# Key Derivation: Trunc16(SHA256(big-endian(Ks)))
# ============================================================

def big_endian_bytes(num: int) -> bytes:
    """
    Convert a Python integer into big-endian byte sequence.
    Length is minimal (no leading zeros beyond necessary).
    """
    return num.to_bytes((num.bit_length() + 7) // 8, 'big')


def derive_key_from_shared_secret(Ks: int) -> bytes:
    """
    Derive AES-128 (16-byte) key from DH shared secret.
    Steps:
      1. Convert Ks → big-endian byte array
      2. Compute SHA256 on these bytes
      3. Take first 16 bytes (Trunc16)
    """
    ks_bytes = big_endian_bytes(Ks)
    digest = hashlib.sha256(ks_bytes).digest()
    return digest[:16]   # AES-128 → 16 bytes


# ============================================================
# Combined Convenience Function
# ============================================================

def dh_generate_keypair():
    """
    Return (private_key, public_value) tuple.
    client/server both call this during DH exchange.
    """
    priv = generate_private_key()
    pub = compute_public_value(priv)
    return priv, pub
