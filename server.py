import socket
import threading
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import pickle

clients = {}
client_certificates = {}

def load_certificates():
    for client_id in ["server", "client1", "client2", "client3"]:
        try:
            with open(f"{client_id}_cert.pem", "rb") as f:
                client_certificates[client_id] = x509.load_pem_x509_certificate(f.read())
            print(f"✅ [DEBUG] Certificate loaded for {client_id}")
        except FileNotFoundError:
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

def handle_authentication(client_socket, client_id):
    try:
        client_certificate = client_certificates[client_id]
        client_public_key = client_certificate.public_key()

        auth_data = client_socket.recv(4096).split(b"||")
        auth_message, signature = auth_data[0].decode(), auth_data[1]

        print(f"🔍 [DEBUG] Auth Message Received: {auth_message}")
        print(f"🔍 [DEBUG] Signature Received: {signature.hex()}")

        if not verify_signature(client_public_key, auth_message, signature):
            print(f"❌ Authentication Failed for {client_id}")
            client_socket.send(b"AUTH_FAILED")
            client_socket.close()
            return False

        client_socket.send(b"AUTH_SUCCESS")
        print(f"✅ Client {client_id} authenticated successfully.")
        return True
    except Exception as e:
        print(f"❌ Authentication error for {client_id}: {e}")
        return False

def handle_client(client_socket, client_id):
    """ Handle communication with clients. """
    while True:
        try:
            encrypted_message = client_socket.recv(4096)
            if not encrypted_message:
                break

            # Forward the encrypted message to the other clients
            for other_client_id, other_client_socket in clients.items():
                if other_client_id != client_id:
                    other_client_socket.send(encrypted_message)
        except Exception as e:
            print(f"❌ Error handling client {client_id}: {e}")
            break

    client_socket.close()
    del clients[client_id]
    print(f"❌ Client {client_id} disconnected.")

def start_server(port):
    load_certificates()
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('0.0.0.0', port))
    server.listen(5)
    print(f"✅ Server listening on port {port}")

    while True:
        client_socket, addr = server.accept()
        print(f"Accepted connection from {addr}")
        client_id = client_socket.recv(1024).decode()

        if handle_authentication(client_socket, client_id):
            clients[client_id] = client_socket
            client_handler = threading.Thread(target=handle_client, args=(client_socket, client_id))
            client_handler.start()

def main():
    ports = [9996, 9997, 9998]
    for port in ports:
        server_thread = threading.Thread(target=start_server, args=(port,))
        server_thread.start()

if __name__ == "__main__":
    main()
