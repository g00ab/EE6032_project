"""
===================================================================================
Crypto Utilities Module (cryptos_utils.py)
===================================================================================

Description:
-------------
This module implements cryptographic functions and utilities for secure communication 
in a multi-client chat system using RSA, AES, and hashing techniques. It is designed to 
support encryption, decryption, message integrity checks, and secure session key exchange.
"""
import os
import socket
import threading
from signature import Actions
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import padding as aes_padding
from cryptography.hazmat.primitives.asymmetric import padding as padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography import x509

# ====================================
# HASHING FUNCTION
# ====================================
def hash_message(message):
    """
    Hashes the provided message using SHA-256 for integrity verification.

    Args:
        message (str or bytes): The message to hash.

    Returns:
        bytes: The computed hash value (32 bytes).
    """
    digest = hashes.Hash(hashes.SHA256())
    digest.update(message if isinstance(message, bytes) else message.encode())
    return digest.finalize()


# ====================================
# AES ENCRYPTION / DECRYPTION
# ====================================
def aes_encrypt(key, plaintext):
    """
    Encrypts plaintext using AES with CBC mode and PKCS7 padding.

    Args:
        key (bytes): The AES key (16 bytes).
        plaintext (str): The message to encrypt.

    Returns:
        dict: Contains 'ciphertext' (encrypted data) and 'iv' (initialization vector).
    """
    iv = os.urandom(16)
    padder = aes_padding.PKCS7(128).padder()
    padded_plaintext = padder.update(plaintext.encode()) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
    return {"ciphertext": ciphertext, "iv": iv}


def aes_decrypt(key, ciphertext, iv):
    """
    Decrypts ciphertext using AES with CBC mode and PKCS7 padding.

    Args:
        key (bytes): The AES key (16 bytes).
        ciphertext (bytes): The encrypted data to decrypt.
        iv (bytes): The 16-byte initialization vector used for encryption.

    Returns:
        str: The decrypted plaintext message.
    """
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = aes_padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    return plaintext.decode()


# ====================================
# MESSAGE SENDING / RECEIVING
# ====================================
def send_message(client_socket, aes_key, message):
    """
    Encrypts and sends a message along with its hash for integrity verification.

    Args:
        client_socket (socket): The client socket to send the message.
        aes_key (bytes): The AES key for encryption.
        message (str): The plaintext message to send.
    """
    try:
        message_hash = hash_message(message)
        encrypted_message = aes_encrypt(aes_key, message)
        iv = encrypted_message["iv"]
        ciphertext = encrypted_message["ciphertext"]
        message_packet = iv + ciphertext + message_hash
        client_socket.send(message_packet)
        print(f"🔍 [DEBUG] Sent encrypted message and hash: {message_packet}")
    except Exception as e:
        print(f"❌ Error during encryption or sending: {e}")


def receive_messages(client, aes_key):
    """
    Receives encrypted messages from the server, decrypts them,
    and verifies the integrity using the hash.

    Args:
        client (socket): The client socket to receive messages.
        aes_key (bytes): The AES key for decryption.
    """
    while True:
        encrypted_message = client.recv(1024)
        if not encrypted_message:
            print("Connection closed.")
            break

        try:
            iv = encrypted_message[:16]
            ciphertext = encrypted_message[16:-32]
            received_hash = encrypted_message[-32:]
            decrypted_message = aes_decrypt(aes_key, ciphertext, iv)
            computed_hash = hash_message(decrypted_message)
            if received_hash == computed_hash:
                print(f"\n\t✅ Hash verified. Decrypted message: {decrypted_message} \n\n")
            else:
                print(f"❌ Hash verification failed. Message may have been tampered with.")
        except Exception as e:
            print(f"Unable to decrypt the received message: {e}")


# ====================================
# SESSION KEY GENERATION / DISTRIBUTION
# ====================================
def generate_session_key_part():
    """
    Generates a random 8-byte session key part for secure key exchange.

    Returns:
        bytes: A randomly generated session key part (8 bytes).
    """
    return os.urandom(8)


def send_session_key_part(client_socket, public_key, sender_id, target_id, session_key_part):
    """
    Encrypts and sends a session key part to the target client via the server.

    Args:
        client_socket (socket): The client socket to send the key part.
        public_key (PublicKey): The RSA public key of the recipient.
        sender_id (str): The ID of the sending client.
        target_id (str): The ID of the intended recipient.
        session_key_part (bytes): The generated session key part.
    """
    try:
        identifier = f"KEY_PART:{sender_id}->{target_id}||".encode('utf-8')
        encrypted_key_part = encrypt(public_key, session_key_part)
        key_part_hash = hash_message(encrypted_key_part)
        client_socket.send(identifier + encrypted_key_part + key_part_hash)
        print(f"✅ Sent session key part and hash from {sender_id} to {target_id}")
    except Exception as e:
        print(f"❌ Error during encryption or sending: {e}")


def receive_session_key_parts(client_socket, private_key, target_id):
    """
    Receives encrypted session key parts, verifies their integrity,
    and decrypts them to construct the final session key.
    
    Args:
        client_socket (socket): The socket through which data is received.
        private_key (RSAPrivateKey): The client's private key for decrypting session key parts.
        target_id (str): The ID of the intended recipient (ensures key parts are correctly assigned).

    Returns:
        dict: A dictionary containing valid decrypted session key parts, indexed by sender IDs.
    """
    session_key_parts = {}
    received_senders = set()
    buffer = b""

    while len(received_senders) < 2:
        data = client_socket.recv(4096)
        if not data:
            print("❌ Connection closed unexpectedly while receiving session key parts.")
            break

        buffer += data

        while b"KEY_PART:" in buffer:
            before_key, buffer = buffer.split(b"KEY_PART:", 1)

            if b'||' not in buffer:
                print("❌ Incomplete or malformed key part detected. Retaining for next packet.")
                continue

            try:
                identifier, rest = buffer.split(b'||', 1)
                if b"KEY_PART:" in rest:
                    encrypted_key_part_and_hash, buffer = rest.split(b"KEY_PART:", 1)
                    buffer = b"KEY_PART:" + buffer
                else:
                    encrypted_key_part_and_hash = rest
                    buffer = b""

                encrypted_key_part = encrypted_key_part_and_hash[:-32]
                received_hash = encrypted_key_part_and_hash[-32:]

                sender_target = identifier.strip().decode('utf-8')
                sender_id, recipient_id = sender_target.split("->")

                if recipient_id != target_id:
                    print(f"❌ Key part intended for {recipient_id}. Ignored.")
                    continue

                if sender_id in received_senders:
                    print(f"❌ Duplicate key part detected from {sender_id}. Ignored.")
                    continue

                computed_hash = hash_message(encrypted_key_part)
                if received_hash != computed_hash:
                    print(f"❌ Hash verification failed for key part from {sender_id}. Ignored.")
                    break
                else:
                    print(f"✅✅ Hash Verified Successfully")

                decrypted_key_part = decrypt(private_key, encrypted_key_part)
                session_key_parts[sender_id] = decrypted_key_part
                received_senders.add(sender_id)
                print(f"✅ Received valid session key part from {sender_id}")

            except Exception as e:
                print(f"❌ Error processing session key part: {e}")
                continue

    print(f"✅ Successfully received {len(received_senders)} valid session key parts.")
    return session_key_parts


# ====================================
# ENCRYPTION / DECRYPTION
# ====================================
def encrypt(public_key, message):
    """
    Encrypts a message using RSA with OAEP padding for confidentiality.

    Args:
        public_key (PublicKey): The RSA public key to use for encryption.
        message (bytes): The message to encrypt.

    Returns:
        bytes: The encrypted message.
    """
    if isinstance(message, str):
        message = message.encode('utf-8')  # Convert string to bytes

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
    """
    Decrypts an RSA-encrypted message.

    Args:
        private_key (PrivateKey): The RSA private key to use for decryption.
        encrypted_message (bytes): The encrypted message to decrypt.

    Returns:
        bytes: The decrypted message if successful, or None if decryption fails.
    """
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


# ====================================
# KEY LOADING
# ====================================
def load_private_key(filename):
    """
    Loads a PEM-formatted RSA private key from a file.

    Args:
        filename (str): Path to the private key file.

    Returns:
        PrivateKey: The loaded RSA private key.
    """
    with open(filename, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None
        )
    return private_key

def load_public_key_from_cert(cert_filename):
    # Load the certificate from a PEM file
    with open(cert_filename, "rb") as cert_file:
        certificate = x509.load_pem_x509_certificate(cert_file.read())
    
    # Extract the public key from the certificate
    public_key = certificate.public_key()

    return public_key

def request_public_key_cert(client_socket, target_client_id):
    """
    Requests a public key for the specified client ID from the server.

    Args:
        client_socket (socket): The socket used to request the public key.
        target_client_id (str): The ID of the client whose public key is needed.

    Returns:
        PublicKey: The retrieved RSA public key.
    """
    client_socket.send(f"REQ_CERT:{target_client_id}".encode('utf-8'))
    public_key_data = client_socket.recv(2048) ### is raw certificate

    if public_key_data.startswith(b"ERROR"):
        print(f"❌ Failed to retrieve public key for {target_client_id}")
        return None
    else:
        public_key = serialization.load_pem_public_key(public_key_data)
        print(f"✅ Public key for {target_client_id} received and stored.")
        return public_key
