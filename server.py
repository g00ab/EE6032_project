import socket
import threading

clients = []  # List to track connected clients

def handle_client(client_socket, client_address):
    """
    Receive messages from a client and forward them to all other clients.
    """
    print(f"Client {client_address} connected.")
    clients.append(client_socket)

    while True:
        try:
            # Receive encrypted message
            message = client_socket.recv(1024)

            if not message:
                break  # Client disconnected

            print(f"Forwarding encrypted message from {client_address}")

            # Forward the encrypted message to all other clients
            forward_message(client_socket, message)

        except:
            break

    # Remove client from list and close connection
    print(f"Client {client_address} disconnected.")
    clients.remove(client_socket)
    client_socket.close()

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

def start_server(port):
    """
    Start a server to handle multiple clients.
    """
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('0.0.0.0', port))
    server.listen(5)

    print(f"Server listening on port {port}")

    while True:
        client_socket, addr = server.accept()
        print(f"Accepted connection from {addr}")

        # Start a new thread for each client
        client_handler = threading.Thread(target=handle_client, args=(client_socket, addr))
        client_handler.start()

# Run the server
def main():
    """
    Start multiple servers on different ports.
    """
    # Define the ports to listen on
    ports = [9996, 9998, 9997]
    
    # Start a server on each port in a separate thread
    for port in ports:
        server_thread = threading.Thread(target=start_server, args=(port,))
        server_thread.start()

if __name__ == "__main__":
    # Call the main function
    main()
