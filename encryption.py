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

    def encrypt(public_key, message):
        """Encrypt a message using the specified public key."""
        encrypted_message = public_key.encrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return encrypted_message

    def decrypt(private_key, encrypted_message):
        """Decrypt a message using the specified private key."""
        try:
            decrypted_message = private_key.decrypt(
                encrypted_message,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return decrypted_message
        except Exception as e:
            print(f"❌ Decryption failed: {e}")
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

