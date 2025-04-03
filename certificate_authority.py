#certifcate_authority.py 
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta

# ========================== CA CREATION ==========================
 
def create_ca():
    """Create a CA key and certificate."""
    # Generate CA private key
    ca_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    # Define CA identity details
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "IE"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "My Secure CA"),
        x509.NameAttribute(NameOID.COMMON_NAME, "MyCA")
    ])

    # Generate CA certificate (self-signed)
    ca_certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(ca_private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=365))  # 1-year validity
        .sign(ca_private_key, hashes.SHA256())
    )

    # Save the CA private key and certificate
    with open("ca_private.key", "wb") as f:
        f.write(ca_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    with open("ca_cert.pem", "wb") as f:
        f.write(ca_certificate.public_bytes(serialization.Encoding.PEM))

    print("✅ CA Certificate Created Successfully!")

    return ca_private_key, ca_certificate

# ========================== CLIENT/SERVER CERTIFICATE CREATION ==========================

def create_certificate(entity_name, ca_private_key, ca_certificate):
    """Create a certificate for a client or server, signed by the CA."""
    # Generate private key for client/server
    entity_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    # Create CSR (Certificate Signing Request)
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "My Organization"),
            x509.NameAttribute(NameOID.COMMON_NAME, entity_name)
        ]))
        .sign(entity_private_key, hashes.SHA256())
    )

    # Sign the CSR with the CA’s private key to generate a certificate
    entity_certificate = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(ca_certificate.subject)
        .public_key(entity_private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=365))
        .sign(ca_private_key, hashes.SHA256())
    )

    # Save private key and certificate
    with open(f"{entity_name}_private.key", "wb") as f:
        f.write(entity_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    with open(f"{entity_name}_cert.pem", "wb") as f:
        f.write(entity_certificate.public_bytes(serialization.Encoding.PEM))

    print(f"✅ {entity_name} Certificate Created Successfully!")

# ========================== MAIN FUNCTION ==========================

def main():
    ca_private_key, ca_certificate = create_ca()

    # Create certificates for server and clients
    create_certificate("server", ca_private_key, ca_certificate)
    create_certificate("client1", ca_private_key, ca_certificate)
    create_certificate("client2", ca_private_key, ca_certificate)
    create_certificate("client3", ca_private_key, ca_certificate)

if __name__ == "__main__":
    main()
