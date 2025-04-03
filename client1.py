# client1.py
from cryptos_utils import *
import socket
import time

def client_program():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('127.0.0.1', 9996))

    client_socket.send(b"client1")

    private_key = load_private_key("client1_private.key")
    actions = Actions(private_key)
    server_public_key = load_public_key_from_cert("server_cert.pem")

    auth_message = "AUTH_REQUEST"
    print(f"🔍 [DEBUG] Auth Message Sent: {auth_message}")
    encrypted_auth_message  = encrypt(server_public_key, auth_message)
    print(f"🔍 [DEBUG] Auth Message Encypted: {encrypted_auth_message }")
    signature = actions.sign_message(auth_message)
    print(f"🔍 [DEBUG] Signature Sent (hex): {signature.hex()}")

    client_socket.send(encrypted_auth_message+"||".encode('utf-8') + signature)

    response_encrypted = client_socket.recv(1024)
    response_decrypted = decrypt(private_key,response_encrypted).decode()
    if response_decrypted != "AUTH_SUCCESS":
        print(response_decrypted)
        print("❌ Authentication Failed!")
        client_socket.close()
        return

    client_id = "client1"
    public_keys = {}
    print("✅ Authentication Successful!")

    client_ids = ["client1", "client2", "client3"]
    target_id = "client3"
    c3public_key = request_public_key_cert(client_socket, target_id)

    pem_data = c3public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

    print(pem_data)
    target_id = "client2"
    c2public_key = request_public_key_cert(client_socket, target_id)
    pem_data = c2public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

    print(pem_data)
    public_keys["client2"] = c2public_key
    public_keys["client3"] = c3public_key

    print("🔍 [DEBUG] Waiting for READY signal...")
    start_message = client_socket.recv(1024).decode().strip()

    if start_message == "READY":
        print("✅ Received READY signal. Proceeding with key exchange.")

        session_key_part = generate_session_key_part()
        print(f"🔑 [DEBUG] Generated session key part for {client_id}: {session_key_part.hex()}")

        for target_id, public_key in public_keys.items():
            print(f"🔍 [DEBUG] Sending session key part to {target_id}")
            send_session_key_part(client_socket, public_key, client_id, target_id, session_key_part)

        session_key_parts = receive_session_key_parts(client_socket, private_key, "client1")
        session_key_parts[client_id] = session_key_part
        print(f"Final session key:  {session_key_parts}")

        sorted_parts = [session_key_parts[key] for key in sorted(session_key_parts.keys(), reverse=True)]
        final_session_key = b"".join(sorted_parts)
        print(f"✅ Final session key: {final_session_key.hex()}")
    else:
        print(f"❌ Unexpected message from server: {start_message}")

    receive_thread = threading.Thread(target=receive_messages, args=(client_socket, final_session_key))
    time.sleep(2)
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