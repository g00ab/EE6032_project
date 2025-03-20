#client2.py
import socket
from encryption import Entity, Actions
from cryptography.hazmat.primitives import serialization
import pickle
import threading
from cryptography.hazmat.primitives.asymmetric import padding
import socket
import threading
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import pickle
from cryptography.hazmat.primitives import serialization
import os  # For generating random session key parts

def generate_session_key_part():
    """
    Generate a random 16-byte session key part.
    """
    return os.urandom(16)  # 16 bytes for AES-128 compatibility

def send_session_key_part(client_socket, public_key, client_id, session_key_part):
    """
    Encrypt and send the session key part to another client.
    """
    identifier = f"KEY_PART:{client_id}||".encode('utf-8')
    encrypted_key_part = encrypt(public_key, session_key_part)
    client_socket.send(identifier + encrypted_key_part)
    print(f"✅ Sent session key part from {client_id}")

def send_session_key_part(client_socket, public_key, sender_id, target_id, session_key_part):
    """
    Encrypt and send the session key part to a targeted client.
    """
    identifier = f"KEY_PART:{sender_id}->{target_id}||".encode('utf-8')
    encrypted_key_part = encrypt(public_key, session_key_part)
    client_socket.send(identifier + encrypted_key_part)
    print(f"✅ Sent session key part from {sender_id} to {target_id}")

def receive_session_key_parts(client_socket, private_key, target_id):
    """
    Receive and decrypt session key parts from other clients.
    Ensures no duplicate keys are accepted, checks the targeted ID, ignores invalid keys,
    and terminates once 2 valid key parts are received.
    """
    session_key_parts = {}
    received_senders = set()  # Tracks received senders to avoid duplicates
    buffer = b""  # Buffer for incomplete data chunks

    while len(received_senders) < 2:  # Exit the loop after receiving 2 valid keys
        data = client_socket.recv(4096)  # Increased buffer size
        if not data:
            print("❌ Connection closed unexpectedly while receiving session key parts.")
            break

        buffer += data  # Append incoming data to buffer

        # Debug: Show received data
        print(f"🔍 [DEBUG] Raw buffer content: {buffer}")

        # Process only complete key parts
        while b"KEY_PART:" in buffer:
            # Split the buffer at the first 'KEY_PART:'
            before_key, buffer = buffer.split(b"KEY_PART:", 1)

            # Handle malformed data before the valid key part
            if b'||' not in buffer:
                print("❌ Incomplete or malformed key part detected. Retaining for next packet.")
                continue  # Wait for more data in the next loop

            # Extract identifier and encrypted key part
            try:
                identifier, rest = buffer.split(b'||', 1)
                if b"KEY_PART:" in rest:
                    # Data has multiple keys packed together; split it
                    encrypted_key_part, buffer = rest.split(b"KEY_PART:", 1)
                    buffer = b"KEY_PART:" + buffer  # Re-add prefix for the next iteration
                else:
                    encrypted_key_part = rest
                    buffer = b""  # Clear buffer after handling full data

                # Parse sender and target IDs
                try:
                    sender_target = identifier.strip().decode('utf-8')
                    sender_id, recipient_id = sender_target.split("->")
                except ValueError:
                    print(f"❌ Invalid identifier format: {identifier}")
                    continue

                # Ensure the targeted ID matches this client
                if recipient_id != target_id:
                    print(f"❌ Key part intended for {recipient_id}. Ignored.")
                    continue

                # Skip duplicates
                if sender_id in received_senders:
                    print(f"❌ Duplicate key part detected from {sender_id}. Ignored.")
                    continue

                # Attempt decryption
                try:
                    decrypted_key_part = decrypt(private_key, encrypted_key_part)
                    session_key_parts[sender_id] = decrypted_key_part
                    received_senders.add(sender_id)
                    print(f"✅ Received valid session key part from {sender_id}")
                except Exception as e:
                    print(f"❌ Decryption failed for {sender_id}: {e}")
                    continue

            except Exception as e:
                print(f"❌ Error processing session key part: {e}")
                continue  # Skip bad data

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
            password=None  # No password needed
        )
    return private_key

def receive_messages(client, private_key):
    while True:
        encrypted_message = client.recv(1024)
        if not encrypted_message:
            break

        # Decrypt the message using the private key
        decrypted_message = decrypt(private_key, encrypted_message)
        if decrypted_message:
            print(f"Decrypted message: {decrypted_message.decode('utf-8')}")
        else:
            print("Unable to decrypt the received message.")


def request_public_key(client_socket, target_client_id):
    """
    Request a single public key for the specified client ID.
    """
    client_socket.send(f"REQ_KEY:{target_client_id}".encode('utf-8'))
    public_key_data = client_socket.recv(2048)

    if public_key_data.startswith(b"ERROR"):
        print(f"❌ Failed to retrieve public key for {target_client_id}")
        return None
    else:
        public_key = serialization.load_pem_public_key(public_key_data)
        print(f"✅ Public key for {target_client_id} received and stored.")
        return public_key


# Client Code
def client_program():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('127.0.0.1', 9997))

    client_socket.send(b"client2")

    private_key = load_private_key("client2_private.key")
    actions = Actions(private_key)  # Pass the loaded private key to Actions

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

    print("✅ Authentication Successful!")
    # rquest public keys from server
    client_id = "client2"
    public_keys = {}
    print("✅ Authentication Successful!")
    # Example usage
    client_ids = ["client1", "client2", "client3"]
    target_id = "client3"
    # Request one public at key at a time
    c3public_key = request_public_key(client_socket, target_id )
    pem_data = c3public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

    print(pem_data)
    target_id = "client1"
    c1public_key = request_public_key(client_socket, target_id )
    pem_data = c1public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

    print(pem_data)
    public_keys["client1"] = c1public_key 
    public_keys["client3"] = c3public_key
        # Wait for "START_KEY_EXCHANGE" signal from the server
    print("🔍 [DEBUG] Waiting for START_KEY_EXCHANGE signal...")
    start_message = client_socket.recv(1024).decode().strip()

    if start_message == "START_KEY_EXCHANGE":
        print("✅ Received START_KEY_EXCHANGE signal. Proceeding with key exchange.")

        # Generate and send the session key part
        session_key_part = generate_session_key_part()
        print(f"🔑 [DEBUG] Generated session key part for {client_id}: {session_key_part.hex()}")

        # Send session key parts to all other clients
        # Send session key parts to all other clients
        for target_id, public_key in public_keys.items():
            print(f"🔍 [DEBUG] Sending session key part to {target_id}")
            send_session_key_part(client_socket, public_key, client_id,target_id, session_key_part)

        # Receive session key parts from other clients
        session_key_parts = receive_session_key_parts(client_socket, private_key, "client2")

        # Add own session key part to the dictionary
        session_key_parts[client_id] = session_key_part
        print(f"Final session key:  {session_key_parts}")
        # Sort and combine session key parts
        sorted_parts = [session_key_parts[key] for key in sorted(session_key_parts.keys(), reverse=True)]
        final_session_key = b"".join(sorted_parts)
        
        print(f"✅ Final session key: {final_session_key.hex()}")
    else:
        print(f"❌ Unexpected message from server: {start_message}")

    # Start a new thread for receiving messages, so the main thread can handle sending.
    #receive_thread = threading.Thread(target=receive_messages, args=(client_socket, private_key))
    #receive_thread.start()

    #while True:
    #    message = input("Enter message: ")
    #    if message.lower() == 'exit':
    #        break

        # Encrypt the message using the public key of the recipient
    #    cipher_text = encrypt(c1public_key, message.encode('utf-8'))  # Encrypt with client2's public key
    #    client_socket.send(cipher_text)


    client_socket.close()

if __name__ == "__main__":
    client_program()
