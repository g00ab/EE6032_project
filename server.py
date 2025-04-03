#server.py
import socket
import threading
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
import time 
from cryptos_utils import *

clients = []
client_certificates = {}
authenticated_clients = 0  # Track number of authenticated clients

def load_certificates():
    for client_id in ["server", "client1", "client2", "client3"]:
        try:
            # Read the PEM file
            with open(f"{client_id}_cert.pem", "rb") as f:
                certificate_data = f.read()  # The raw PEM-encoded certificate

            # Load the certificate object
            client_certificates[client_id] = x509.load_pem_x509_certificate(certificate_data)

            # Print debug message
            print(f"✅ [DEBUG] Certificate loaded for {client_id}")
            
            # Print the raw PEM certificate data
            print(f"cert id {client_id} cert:\n{certificate_data.decode('utf-8')}")

        except FileNotFoundError:
            # Print error message for missing file
            print(f"❌ [ERROR] Missing certificate for {client_id}")

def verify_signature(public_key, message, signature):
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

def forward_message(sender_socket, message):
    """
    Forward encrypted messages to all clients except the sender.
    """
    for client in clients:
        if client != sender_socket:
            try:
                client.send(message)  # Forward encrypted message exactly as received
            except:
                client.close()
                clients.remove(client)

def strip_outer_bytes(data):
    # Check if the data is double-encoded
    if isinstance(data, bytes):
        # Decode the outer layer
        decoded_data = data.decode('utf-8')

        # Check if the inner data is still encoded as bytes (e.g., starts with b')
        if decoded_data.startswith("b'") or decoded_data.startswith('b"'):
            # Strip the b'' or b"" wrapping
            inner_data = eval(decoded_data)  # Convert string representation back to bytes
            return inner_data

    return data  # Return data unchanged if not double-encoded
                  
def handle_authentication(client_socket, server_private_key, client_id):
    global authenticated_clients  # To track the number of authenticated clients
    try:
        client_certificate = client_certificates[client_id]
        client_public_key = client_certificate.public_key()
        auth_data = client_socket.recv(4096).split(b"||")

        # Extract and decrypt the auth message (don't decode it yet)
        encrypted_auth_message = auth_data[0]
        signature = auth_data[1]

        # Decrypt the auth message using the server's private key
        auth_message = decrypt(server_private_key, encrypted_auth_message)

        print(f"🔍 [DEBUG] Auth Message Received: {auth_message}")
        print(f"🔍 [DEBUG] Signature Received: {signature.hex()}")

        if not verify_signature(client_public_key, auth_message.decode(), signature):
            print(f"❌ Authentication Failed for {client_id}")
            client_socket.send(b"AUTH_FAILED")
            client_socket.close()
            return False

        response_message =b"AUTH_SUCCESS"
        client_socket.send(encrypt(client_public_key, response_message))
        print(f"✅ Client {client_id} authenticated successfully.")
        authenticated_clients += 1  # Increment authenticated client count

        return True
    except Exception as e:
        print(f"❌ Authentication error for {client_id}: {e}")
        return False



def handle_client(client_socket, client_address):
    """
    Receive messages from a client, handle public key requests,
    and forward session key parts and encrypted messages.
    """
    global ready_clients  # List to track clients that are ready for key exchang
    print(f"Client {client_address} connected.")
    print(f"*****client to append{client_socket}")
    clients.append(client_socket)

    while True:
        try:
            # Receive data from the client
            raw_request_data = client_socket.recv(4096) 
            
            if not raw_request_data:
                break  # Client disconnected

            # Decode and process textual requests
            try:
                request_data = raw_request_data.decode('utf-8').strip()
            except UnicodeDecodeError:
                request_data = None  # Non-textual data (e.g., encrypted or binary data)

            if request_data:
                if request_data.startswith("REQ_CERT:"):
                    # Handle public key request
                    requested_client_id = request_data.split(":")[1].strip()
                    if requested_client_id in client_certificates:
                        requested_public_key = client_certificates[requested_client_id].public_key()
                        pem_data = requested_public_key.public_bytes(
                            encoding=serialization.Encoding.PEM,
                            format=serialization.PublicFormat.SubjectPublicKeyInfo
                        )
                        client_socket.send(pem_data)
                    else:
                        client_socket.send(b"ERROR: Public key not found.")
                else:
                    print(f"🔍 [DEBUG] Received unsupported text request: {request_data}")
            else:
                # Binary data processing (session key parts or encrypted messages)
                if raw_request_data.startswith(b"KEY_PART:"):
                    # Forward session key parts to all clients except the sender
                    print(f"🔑 [DEBUG] Forwarding session key part from {client_address}")
                    forward_message(client_socket, raw_request_data)
                else:
                    # Assume it's an encrypted message and forward it
                    print(f"🔍 [DEBUG] Forwarding encrypted message from {client_address}")
                    forward_message(client_socket, raw_request_data)

        except Exception as e:
            print(f"❌ Error handling client {client_address}: {e}")
            break

    # Cleanup on disconnect
    print(f"Client {client_address} disconnected.")
    clients.remove(client_socket)
    client_socket.close()


def start_server(port):
    load_certificates()
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('0.0.0.0', port))
    server.listen(5)
    print(f"✅ Server listening on port {port}")
    server_private_key = load_private_key("server_private.key")
    server_public_key = load_public_key_from_cert("server_cert.pem")
    while True:
        client_socket, addr = server.accept()
        print(f"Accepted connection from {addr}")
        client_id = client_socket.recv(1024).decode()

        if handle_authentication(client_socket, server_private_key, client_id):

            client_handler = threading.Thread(target=handle_client, args=(client_socket, addr))
            client_handler.start()
            time.sleep(1)
            if authenticated_clients == 3:
                print("✅ All 3 clients authenticated. Broadcasting key exchange signal.")
                for client in clients:
                    client.send(b"READY")
                    print(f"Client ready {client}")   

def main():
    ports = [9996, 9997, 9998]
    for port in ports:
        server_thread = threading.Thread(target=start_server, args=(port,))
        server_thread.start()

if __name__ == "__main__":
    main()
