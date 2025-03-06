from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import hashlib
import os

# Import your Entity and Actions classes
from encryption import Entity, Actions  # Replace 'your_module' with your actual filename

def test_rsa_encryption():
    print("\n🔹 **TESTING RSA ENCRYPTION & DECRYPTION**")
    entity = Entity()  # Generate RSA key pair
    actions = Actions(entity)

    message = b"Secure communication test"
    encrypted_message = actions.encrypt(message)  # Encrypt message
    decrypted_message = actions.decrypt()  # Decrypt message

    assert decrypted_message == message, "❌ RSA Decryption Failed!"
    print("✅ RSA Encryption & Decryption Passed!")


def test_hashing():
    print("\n🔹 **TESTING HASHING FUNCTION**")
    actions = Actions(Entity())

    message = "secure_password"
    stored_hash, original_message = actions.hashing(message)  # Hash message

    assert actions.compare_hashing(stored_hash, original_message), "❌ Hashing Failed!"
    print("✅ Hashing Passed!")


def test_signatures():
    print("\n🔹 **TESTING DIGITAL SIGNATURES**")
    entity = Entity()
    actions = Actions(entity)

    message = "This is a signed message"
    signature = actions.sign_message(message)  # Sign message
    assert actions.verify_signature(message, signature), "❌ Signature Verification Failed!"
    
    print("✅ Digital Signatures Passed!")

    
def run_tests():
    test_rsa_encryption()
    test_hashing()
    test_signatures()
    print("\n🎉 ALL TESTS PASSED SUCCESSFULLY!")

if __name__ == "__main__":
    run_tests()
