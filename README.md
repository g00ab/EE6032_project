
# Secure Client-Server Communication with Key Exchange

This project implements a secure client-server communication system that leverages digital signatures and public key encryption for authentication and secure messaging between clients.

## Features

- **Client Authentication**: Clients are authenticated using certificates and digital signatures. Each client has a unique certificate that is validated during the authentication process.
- **Session Key Exchange**: Once authenticated, clients participate in a secure session key exchange using public key encryption.
- **Message Forwarding**: Encrypted messages and session key parts are forwarded to other authenticated clients, enabling secure communication.
- **Multi-client Support**: The server supports communication with multiple clients and handles authentication for each client separately.

## Requirements

- Python 3.x
- `cryptography` library for handling certificates and encryption
- Clients must have valid certificates (`client1_cert.pem`, `client2_cert.pem`, `client3_cert.pem`, and `server_cert.pem`)

## Setup

### 1. Install Dependencies

To install the required Python libraries, use the following command:

```bash
pip install cryptography
```

### 2. Certificates

Ensure that the following PEM-encoded certificates are present in the directory where the server is run:

- `server_cert.pem`
- `client1_cert.pem`
- `client2_cert.pem`
- `client3_cert.pem`

These certificates will be used for client authentication.

### 3. Running the Server

To start the server, run the script:

```bash
python server.py
```

The server will listen for connections from clients on the following ports:

- `9996`
- `9997`
- `9998`

The server will handle multiple clients using threads, allowing for simultaneous communication.

### 4. Client Authentication

Each client will be authenticated using their certificate. The client sends an authentication message along with a digital signature. The server verifies the signature using the client’s public key (extracted from the certificate).

- Upon successful authentication, the server sends an acknowledgment message.
- If authentication fails, the server closes the connection.

### 5. Public Key Request

Once authenticated, clients can request each other’s public keys for secure communication. A client sends a request to the server in the format:

```
REQ_KEY:<client_id>
```

The server will send the requested client's public key in PEM format.

### 6. Key Exchange

When all clients are authenticated, the server broadcasts a `START_KEY_EXCHANGE` message to all connected clients. Clients will then exchange encrypted session keys securely.

### 7. Sending Messages

After key exchange, clients can send encrypted messages to the server. The server forwards these encrypted messages to other clients, enabling secure communication between them.

### 8. Disconnecting

When a client disconnects, the server cleans up the client’s connection and removes it from the list of connected clients.

## Code Overview

### `server.py`

This script contains the server implementation that handles:

- **Loading Certificates**: Loads client and server certificates from PEM files.
- **Authentication**: Authenticates clients using certificates and digital signatures.
- **Key Exchange**: Manages session key exchange after all clients are authenticated.
- **Message Forwarding**: Forwards encrypted messages and key parts to other clients.

### Key Functions

- `load_certificates()`: Loads the certificates for the server and clients.
- `verify_signature()`: Verifies the digital signature of an authentication message.
- `handle_authentication()`: Handles the client authentication process.
- `handle_public_key_request()`: Handles requests for public keys.
- `forward_message()`: Forwards encrypted messages to all clients except the sender.
- `handle_client()`: Main handler for client communication, processing requests and messages.
- `start_server()`: Initializes the server, listens for incoming connections, and manages client threads.
- `main()`: Starts the server on multiple ports for handling different clients.

## Example Usage

1. **Start the server** by running `server.py`.
2. **Clients connect** to the server and authenticate using their certificates.
3. **Key exchange** begins once all clients are authenticated.
4. Clients can send encrypted messages, which the server forwards to all other authenticated clients.

## Troubleshooting

- **Missing Certificates**: Ensure that the certificates for the server and clients are available in the correct directory.
- **Connection Issues**: Check that the server is running and accessible on the specified ports.
- **Authentication Failure**: Ensure that the client sends a valid signature and message during the authentication step.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
