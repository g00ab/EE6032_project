#client1.py
import socket
from encryption import Entity, Actions
from cryptography.hazmat.primitives import serialization
import pickle

def load_private_key(filename):
    with open(filename, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None  # No password needed
        )
    return private_key

def client_program():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('127.0.0.1', 9996))

    client_socket.send(b"client1")

    private_key = load_private_key("client1_private.key")
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

    # Step 2: Establish Session Key (Kabc) using Diffie-Hellman Key Exchange
    dh_params = actions.generate_dh_parameters()
    print(f"🔍 [DEBUG] DH Parameters Generated: {dh_params}")
    client_socket.send(pickle.dumps(dh_params))  # Send DH parameters to the server

    dh_public_key = actions.generate_dh_public_key()
    print(f"🔍 [DEBUG] DH Public Key Generated: {dh_public_key.hex()}")
    client_socket.send(dh_public_key)  # Send DH public key to the server

    # Receive public keys from other entities (B and C)
    peer_public_keys = []
    for _ in range(2):
        peer_public_key = client_socket.recv(4096)
        print(f"🔍 [DEBUG] Received Peer Public Key: {peer_public_key.hex()}")
        peer_public_keys.append(peer_public_key)

    # Exchange and establish shared key (Kabc)
    #for peer_public_key in peer_public_keys:
    #    shared_key = actions.exchange_shared_key(peer_public_key)
    #    print(f"🔍 [DEBUG] Shared Key Established: {shared_key.hex()}")

    print("✅ Session Key Established!")

    while True:
        message = input("Enter message: ")
        if message.lower() == 'exit':
            break

        cipher_text = actions.encrypt(message.encode('utf-8'))
        client_socket.send(cipher_text)

    client_socket.close()

if __name__ == "__main__":
    client_program()
