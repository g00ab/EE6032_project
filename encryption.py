#enryption.py
import hashlib
import socket
from cryptography.hazmat.primitives import serialization, hashes, hmac
from cryptography.hazmat.primitives.asymmetric import dh, rsa, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import pickle

class Entity:
    def __init__(self):
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.public_key = self.private_key.public_key()

    def key_generation(self):
        private_pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        public_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return private_pem.decode(), public_pem.decode()

class Actions:
    def __init__(self, private_key):
        self.private_key = private_key
        self.public_key = private_key.public_key()
        self.ciphertext = None

    def encrypt(self, message):
        """Encrypt a message and sign it."""
        signature = self.sign_message(message.decode())
        message_with_signature = message + b"||" + signature
        self.ciphertext = self.public_key.encrypt(
            message_with_signature,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
        return self.ciphertext

    def decrypt(self, encrypted_message):
        """Decrypt a message and verify its signature."""
        plaintext = self.private_key.decrypt(
            encrypted_message,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
        message, signature = plaintext.rsplit(b'||', 1)
        if self.verify_signature(message.decode(), signature):
            return message
        else:
            print("Message Integrity Compromised!")
            return None

    def sign_message(self, message):
        encoded_message = message.strip().encode('utf-8')
        print(f"🔍 [DEBUG] Message before signing: {message}")
        print(f"🔍 [DEBUG] Encoded message (before signing): {encoded_message}")

        signature = self.private_key.sign(
            encoded_message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()), 
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        print(f"✅ [DEBUG] Signature (binary): {signature}")
        print(f"✅ [DEBUG] Signature (hex): {signature.hex()}")
        return signature

    def verify_signature(self, public_key, message, signature):
        try:
            encoded_message = message.strip().encode('utf-8')
            print(f"🔍 [DEBUG] Encoded message (for verification): {encoded_message}")
            print(f"🔍 [DEBUG] Signature received (binary): {signature}")
            print(f"🔍 [DEBUG] Signature received (hex): {signature.hex()}")

            public_key.verify(
                signature,
                encoded_message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.AUTO
                ),
                hashes.SHA256()
            )
            print("✅ Signature Verified Successfully!")
            return True
        except Exception as e:
            print(f"❌ Signature Verification Failed: {e}")
            return False
    # for session key

    def generate_dh_parameters(self):
        parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
        self.diffie_hellman_parameters = parameters
        return parameters.parameter_bytes(serialization.Encoding.PEM, serialization.ParameterFormat.PKCS3)

    def generate_dh_public_key(self):
        private_key = self.diffie_hellman_parameters.generate_private_key()
        self.private_key_dh = private_key
        return private_key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)

    def exchange_shared_key(self, peer_public_key):
        # Load the peer's public key from PEM format
        peer_key = serialization.load_pem_public_key(peer_public_key, backend=default_backend())
        
        # Ensure the peer's key is a valid Diffie-Hellman public key
        if not isinstance(peer_key, dh.DHPublicKey):
            raise TypeError("The peer public key must be a Diffie-Hellman public key.")
        
        # Perform the key exchange using the Diffie-Hellman private key and peer's public key
        shared_key = self.private_key_dh.exchange(peer_key)
        
        # Store and return the shared key
        self.shared_key = shared_key
        return self.shared_key
