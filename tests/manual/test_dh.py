import sys
import os

# -------- Add project root to Python path --------
project_root = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
sys.path.append(project_root)
print(f"DEBUG: Added project root to PYTHONPATH: {project_root}")

# -------- Try importing DH functions --------
try:
    from app.crypto.dh import (
        dh_generate_keypair,
        compute_shared_secret,
        derive_key_from_shared_secret
    )
except ImportError as e:
    print("ERROR: Failed to import DH functions:", e)
    sys.exit(1)

# -------- Test function --------
def test_dh_key_exchange():
    print("=== DH STEP 3 TEST ===")

    # -------- CLIENT GENERATES KEYS --------
    client_private, client_public = dh_generate_keypair()
    print(f"Client private: {client_private}")
    print(f"Client public: {client_public}")

    # -------- SERVER GENERATES KEYS --------
    server_private, server_public = dh_generate_keypair()
    print(f"Server private: {server_private}")
    print(f"Server public: {server_public}")

    # -------- COMPUTE SHARED SECRET --------
    Ks_client = compute_shared_secret(server_public, client_private)
    Ks_server = compute_shared_secret(client_public, server_private)

    print(f"Client Ks: {Ks_client}")
    print(f"Server Ks: {Ks_server}")

    assert Ks_client == Ks_server, "ERROR: Shared secrets DO NOT match!"
    print("Shared secret matches ✔")

    # -------- DERIVE SESSION KEY --------
    client_key = derive_key_from_shared_secret(Ks_client)
    server_key = derive_key_from_shared_secret(Ks_server)

    print(f"Client AES key: {client_key.hex()}")
    print(f"Server AES key: {server_key.hex()}")

    assert client_key == server_key, "ERROR: Derived AES keys DO NOT match!"
    print("AES-128 derived session key matches ✔")
    print("=== DH TEST SUCCESS ===")


# -------- Run the test if executed directly --------
if __name__ == "__main__":
    try:
        test_dh_key_exchange()
    except AssertionError as ae:
        print("ASSERTION FAILED:", ae)
    except Exception as e:
        print("ERROR during test execution:", e)
