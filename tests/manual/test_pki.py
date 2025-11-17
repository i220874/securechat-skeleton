import sys, os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))


from app.crypto.pki import load_certificate_from_file, verify_certificate_chain, verify_hostname

def test_pki():
    ca = load_certificate_from_file("certs/ca.cert.pem")
    server = load_certificate_from_file("certs/server.cert.pem")

    verify_certificate_chain(server, ca)
    verify_hostname(server, "server.local")

    print("TEST OK: Certificate validation works!")

if __name__ == "__main__":
    test_pki()
