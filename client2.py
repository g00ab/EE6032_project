# client2.py
import socket
from encryption import Actions
from cryptography.hazmat.primitives import serialization
import threading
from cryptography.hazmat.primitives.asymmetric import padding as padding
from cryptography.hazmat.primitives import padding as aes_padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

# Function to hash a message using SHA-256
def hash_message(message):
    """Hash the message using SHA-256."""
    digest = hashes.Hash(hashes.SHA256())
    # Convert to bytes if the message is not already in bytes
    digest.update(message if isinstance(message, bytes) else message.encode())
    return digest.finalize()

# Function to encrypt plaintext using AES in CBC mode with PKCS7 padding
def aes_encrypt(key, plaintext):
    """Encrypts plaintext using AES with CBC mode and PKCS7 padding."""
    iv = os.urandom(16)  # Generate a random initialization vector (IV)
    padder = aes_padding.PKCS7(128).padder()  # Create a PKCS7 padder
    padded_plaintext = padder.update(plaintext.encode()) + padder.finalize()  # Pad the plaintext
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())  # Create AES cipher
    encryptor = cipher.encryptor()  # Create encryptor
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()  # Encrypt the padded plaintext
    return {"ciphertext": ciphertext, "iv": iv}  # Return ciphertext and IV

# Function to decrypt ciphertext using AES in CBC mode with PKCS7 padding
def aes_decrypt(key, ciphertext, iv):
    """Decrypts ciphertext using AES with CBC mode and PKCS7 padding."""
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())  # Create AES cipher
    decryptor = cipher.decryptor()  # Create decryptor
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()  # Decrypt the ciphertext
    unpadder = aes_padding.PKCS7(128).unpadder()  # Create PKCS7 unpadder
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()  # Remove padding
    return plaintext.decode()  # Return the plaintext as a string

# Function to send an encrypted message along with its hash
def send_message(client_socket, aes_key, message):
    """Encrypt and send a message along with its hash."""
    try:
        message_hash = hash_message(message)  # Compute hash of the message
        encrypted_message = aes_encrypt(aes_key, message)  # Encrypt the message
        iv = encrypted_message["iv"]  # Extract IV
        ciphertext = encrypted_message["ciphertext"]  # Extract ciphertext
        message_packet = iv + ciphertext + message_hash  # Combine IV, ciphertext, and hash
        client_socket.send(message_packet)  # Send the packet over the socket
        print(f"🔍 [DEBUG] Sent encrypted message and hash: {message_packet}")
    except Exception as e:
        print(f"❌ Error during encryption or sending: {e}")

# Function to receive and decrypt messages, and verify their hash
def receive_messages(client, aes_key):
    """Receive and decrypt messages using AES, and verify the hash."""
    while True:
        encrypted_message = client.recv(1024)  # Receive encrypted message
        if not encrypted_message:
            print("Connection closed.")
            break

        try:
            iv = encrypted_message[:16]  # Extract IV (first 16 bytes)
            ciphertext = encrypted_message[16:-32]  # Extract ciphertext (excluding IV and hash)
            received_hash = encrypted_message[-32:]  # Extract hash (last 32 bytes)
            decrypted_message = aes_decrypt(aes_key, ciphertext, iv)  # Decrypt the ciphertext
            computed_hash = hash_message(decrypted_message)  # Compute hash of the decrypted message
            if received_hash == computed_hash:  # Verify the hash
                print(f"✅ Hash verified. Decrypted message: {decrypted_message}")
            else:
                print(f"❌ Hash verification failed. Message may have been tampered with.")
        except Exception as e:
            print(f"Unable to decrypt the received message: {e}")

# Function to generate a random 16-byte session key part
def generate_session_key_part():
    """Generate a random 16-byte session key part."""
    return os.urandom(8)

# Function to encrypt and send a session key part to a target client
def send_session_key_part(client_socket, public_key, sender_id, target_id, session_key_part):
    """Encrypt and send the session key part to a targeted client, including its hash."""
    try:
        identifier = f"KEY_PART:{sender_id}->{target_id}||".encode('utf-8')  # Create identifier
        encrypted_key_part = encrypt(public_key, session_key_part)  # Encrypt the session key part
        key_part_hash = hash_message(encrypted_key_part)  # Compute hash of the encrypted key part
        # Send the identifier, encrypted key part, and hash together
        client_socket.send(identifier + encrypted_key_part + key_part_hash)
        print(f"✅ Sent session key part and hash from {sender_id} to {target_id}")
    except Exception as e:
        print(f"❌ Error during encryption or sending: {e}")

# Function to receive and process session key parts
def receive_session_key_parts(client_socket, private_key, target_id):
    """Receive and decrypt session key parts, verify their hashes for integrity."""
    session_key_parts = {}  # Dictionary to store session key parts
    received_senders = set()  # Set to track senders
    buffer = b""  # Buffer to handle partial data

    while len(received_senders) < 2:  # Wait until two key parts are received
        data = client_socket.recv(4096)  # Receive data
        if not data:
            print("❌ Connection closed unexpectedly while receiving session key parts.")
            break

        buffer += data  # Append data to buffer

        while b"KEY_PART:" in buffer:  # Process each key part in the buffer
            before_key, buffer = buffer.split(b"KEY_PART:", 1)

            if b'||' not in buffer:  # Check for incomplete key part
                print("❌ Incomplete or malformed key part detected. Retaining for next packet.")
                continue

            try:
                # Parse identifier and encrypted key part with hash
                identifier, rest = buffer.split(b'||', 1)
                if b"KEY_PART:" in rest:
                    encrypted_key_part_and_hash, buffer = rest.split(b"KEY_PART:", 1)
                    buffer = b"KEY_PART:" + buffer
                else:
                    encrypted_key_part_and_hash = rest
                    buffer = b""

                # Extract encrypted key part and hash
                encrypted_key_part = encrypted_key_part_and_hash[:-32]
                received_hash = encrypted_key_part_and_hash[-32:]

                # Decode identifier and verify target recipient
                sender_target = identifier.strip().decode('utf-8')
                sender_id, recipient_id = sender_target.split("->")
                if recipient_id != target_id:
                    print(f"❌ Key part intended for {recipient_id}. Ignored.")
                    continue
                else: 
                    print(f"✅✅ Hash Verified Successfully")

                if sender_id in received_senders:
                    print(f"❌ Duplicate key part detected from {sender_id}. Ignored.")
                    continue

                # Verify the hash of the encrypted key part
                computed_hash = hash_message(encrypted_key_part)
                if received_hash != computed_hash:
                    print(f"❌ Hash verification failed for key part from {sender_id}. Ignored.")
                    continue

                # Decrypt the key part
                decrypted_key_part = decrypt(private_key, encrypted_key_part)
                session_key_parts[sender_id] = decrypted_key_part
                received_senders.add(sender_id)
                print(f"✅ Received valid session key part from {sender_id}")

            except Exception as e:
                print(f"❌ Error processing session key part: {e}")
                continue

    print(f"✅ Successfully received {len(received_senders)} valid session key parts.")
    return session_key_parts

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

def load_private_key(filename):
    with open(filename, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None
        )
    return private_key

def request_public_key(client_socket, target_client_id):
    """Request a single public key for the specified client ID."""
    client_socket.send(f"REQ_KEY:{target_client_id}".encode('utf-8'))
    public_key_data = client_socket.recv(2048)

    if public_key_data.startswith(b"ERROR"):
        print(f"❌ Failed to retrieve public key for {target_client_id}")
        return None
    else:
        public_key = serialization.load_pem_public_key(public_key_data)
        print(f"✅ Public key for {target_client_id} received and stored.")
        return public_key

def client_program():
    # DIFFERENCE: Connect to port 9997 for client2
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('127.0.0.1', 9997))

    # DIFFERENCE: Send client ID as "client2"
    client_socket.send(b"client2")

    # DIFFERENCE: Load client2's private key
    private_key = load_private_key("client2_private.key")
    actions = Actions(private_key)

    auth_message = "AUTH_REQUEST"
    print(f"🔍 [DEBUG] Auth Message Sent: {auth_message}")

    signature = actions.sign_message(auth_message)
    print(f"🔍 [DEBUG] Signature Sent (hex): {signature.hex()}")

    client_socket.send(f"{auth_message}||".encode('utf-8') + signature)

    response = client_socket.recv(1024).decode()
    if response != "AUTH_SUCCESS":
        print(response)
        print("❌ Authentication Failed!")
        client_socket.close()
        return

    # DIFFERENCE: Set client ID to "client2"
    client_id = "client2"
    public_keys = {}
    print("✅ Authentication Successful!")

    client_ids = ["client1", "client2", "client3"]
    target_id = "client3"
    c3public_key = request_public_key(client_socket, target_id)
    pem_data = c3public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

    print(pem_data)
    target_id = "client1"
    c1public_key = request_public_key(client_socket, target_id)
    pem_data = c1public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

    print(pem_data)
    public_keys["client1"] = c1public_key
    public_keys["client3"] = c3public_key

    print("🔍 [DEBUG] Waiting for START_KEY_EXCHANGE signal...")
    start_message = client_socket.recv(1024).decode().strip()

    if start_message == "START_KEY_EXCHANGE":
        print("✅ Received START_KEY_EXCHANGE signal. Proceeding with key exchange.")

        session_key_part = generate_session_key_part()
        print(f"🔑 [DEBUG] Generated session key part for {client_id}: {session_key_part.hex()}")

        for target_id, public_key in public_keys.items():
            print(f"🔍 [DEBUG] Sending session key part to {target_id}")
            send_session_key_part(client_socket, public_key, client_id, target_id, session_key_part)

        session_key_parts = receive_session_key_parts(client_socket, private_key, "client2")
        session_key_parts[client_id] = session_key_part
        print(f"Final session key:  {session_key_parts}")

        sorted_parts = [session_key_parts[key] for key in sorted(session_key_parts.keys(), reverse=True)]
        final_session_key = b"".join(sorted_parts)
        print(f"✅ Final session key: {final_session_key.hex()}")
    else:
        print(f"❌ Unexpected message from server: {start_message}")

    receive_thread = threading.Thread(target=receive_messages, args=(client_socket, final_session_key))
    receive_thread.start()

    while True:
        message = input("Enter message: ")
        if message.lower() == 'exit':
            print("Exiting...")
            break

        send_message(client_socket, final_session_key, message)

    client_socket.close()

if __name__ == "__main__":
    client_program()