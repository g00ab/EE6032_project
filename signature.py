# ====================================================
# ENCRYPTION MODULE - Digital Signatures & RSA Utilities
# ====================================================
# This module provides cryptographic utilities for:
# - RSA Key Generation
# - Digital Signature Creation & Verification
# - Ensuring Data Integrity and Authenticity
# 
# Each class and function is documented for clarity.
# ====================================================

import hashlib
import socket
from cryptography.hazmat.primitives import serialization, hashes, hmac
from cryptography.hazmat.primitives.asymmetric import rsa, padding

# ====================================
# ENTITY CLASS - RSA Key Generation
# ====================================
class Entity:
    """
    Represents an entity that generates RSA keys for secure communication.
    
    Attributes:
        - private_key (RSAPrivateKey): The private RSA key used for signing and decryption.
        - public_key (RSAPublicKey): The public RSA key used for verification and encryption.
    """
    def __init__(self):
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.public_key = self.private_key.public_key()

# ====================================
# ACTIONS CLASS - Signature & Verification
# ====================================
class Actions:
    """
    Provides functionality to sign and verify messages using RSA digital signatures.
    
    Attributes:
        - private_key (RSAPrivateKey): The private key for signing messages.
        - public_key (RSAPublicKey): The corresponding public key for verification.
    """
    def __init__(self, private_key):
        self.private_key = private_key
        self.public_key = private_key.public_key()
        self.ciphertext = None

    def sign_message(self, message):
        """
        Digitally signs a message using RSA-PSS with SHA-256 for integrity and authenticity.
        
        Process:
        --------
        1. The message is encoded to bytes.
        2. The encoded message is signed using the entity’s private RSA key.
        3. PSS padding ensures maximum security for RSA signatures.
        
        Args:
            message (str): The message to be signed.

        Returns:
            bytes: The generated digital signature.
        """
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
        """
        Verifies the authenticity of a signed message using the provided public key.

        Process:
        --------
        1. The original message is encoded to bytes.
        2. The received signature is verified against the encoded message.
        3. If successful, the message's authenticity and integrity are confirmed.

        Args:
            public_key (RSAPublicKey): The RSA public key for signature verification.
            message (str): The original message to be verified.
            signature (bytes): The digital signature to be verified.

        Returns:
            bool: True if the signature is valid; False otherwise.
        """
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
  

