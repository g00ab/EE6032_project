import socket
import threading

clients = []

def handle_client(client_socket, client_address):
    while True:
        try:
            message = client_socket.recv(1024).decode('utf-8')
            if not message:
                break
            print(f"Received from {client_address}: {message}")
            forward_message(client_socket, message)
        except:
            break
    client_socket.close()
    clients.remove(client_socket)

def forward_message(sender_socket, message):
    for client in clients:
        if client != sender_socket:
            try:
                client.send(f"Forwarded: {message}".encode('utf-8'))
            except:
                client.close()
                clients.remove(client)

def start_server(port):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('0.0.0.0', port))
    server.listen(3)
    print(f"Server listening on port {port}")

    while True:
        client_socket, addr = server.accept()
        print(f"Accepted connection from {addr}")
        clients.append(client_socket)
        client_handler = threading.Thread(target=handle_client, args=(client_socket, addr))
        client_handler.start()

def main():
    ports = [9996, 9998, 9997]
    for port in ports:
        server_thread = threading.Thread(target=start_server, args=(port,))
        server_thread.start()

if __name__ == "__main__":
    main()
