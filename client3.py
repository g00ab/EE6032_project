import socket  
import encryption  
import threading 

def receive_messages(client, actions):
    """
    Function to receive and decrypt messages from the server in a separate thread.
    Parameters:
        client: The connected client socket.
        actions: The encryption actions instance for encryption/decryption.
    """
    while True:
        # Receive an encrypted message from the server.
        encrypted_message = client.recv(1024)
        
        # Check if the connection was closed or no message was received.
        if not encrypted_message:
            break

        try:
            # Attempt to decrypt the received message and decode it to a UTF-8 string.
            decrypted_message = actions.decrypt(encrypted_message).decode('utf-8')
            print(f"Decrypted message: {decrypted_message}")  # Display the decrypted message.
        except:
            # Handle cases where the message could not be decrypted.
            print(f"Received an encrypted message but could not decrypt: {encrypted_message}")

def main():
    """
    Main function to set up the client, initiate the connection, and handle message input and sending.
    """
    # Create a client socket using IPv4 and TCP protocol.
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    # Connect to the server using localhost (127.0.0.1) and port 9996.
    client.connect(('127.0.0.1', 9997))

    # Initialize the encryption entity and actions for secure communication.
    entity = encryption.Entity()  # Create an encryption entity (assumed to hold keys or configurations).
    actions = encryption.Actions(entity)  # Create an encryption actions instance.

    # Start a new thread for receiving messages, so the main thread can handle sending.
    receive_thread = threading.Thread(target=receive_messages, args=(client, actions))
    receive_thread.start()

    while True:
        # Prompt the user to enter a message.
        message = input("Enter message: ")

        # Exit the loop if the user types 'exit'.
        if message.lower() == 'exit':
            break

        # Encrypt the user’s message and send it to the server.
        cipher_text = actions.encrypt(message.encode('utf-8'))  # Convert the message to bytes and encrypt it.
        client.send(cipher_text)  # Send the encrypted message.

    # Close the client socket after exiting the loop.
    client.close()

# Check if the script is being run directly (not imported).
if __name__ == "__main__":
    main()  # Execute the main function.
