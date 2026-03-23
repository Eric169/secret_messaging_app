# Cryptographic Chat Application

An end-to-end encrypted chat application implemented in Python, featuring custom cryptographic primitives and a secure communication protocol.

## Features

- **End-to-End Encryption**: Messages are encrypted using DES with unique session keys.
- **Secure Key Exchange**: Diffie-Hellman (DH) key exchange is used to derive session keys, protected by RSA.
- **Hybrid Password Hashing**: Passwords are pre-hashed on the client (SHA256) and then hashed with salted PBKDF2 (100,000 iterations) on the server.
- **Message Reliability**: Automatic retry logic (3 attempts) for server communication.
- **Persistent Storage**: SQLite databases for both client and server, with client data organized in `client/dbs/`.

## Prerequisites

- Python 3.8+
- `tkinter` (Standard library, but on Linux may require `sudo apt install python3-tk`)

## Installation

No external pip packages are required. Clone the repository and ensure you have the correct Python version.

## Usage

### 1. Start the Server
Run the server from the root directory:
```bash
python3 -m server.server
```
By default, the server listens on `127.0.0.1:12345`.

### 2. Run the Client
Open a new terminal and run the client:
```bash
python3 -m client.client
```
The GUI will allow you to register a new user or login with an existing one.

> [!TIP]
> Registration can take a significant amount of time (30-60 seconds) because the pure Python implementation generates 2048-bit random primes for RSA keys. For faster testing, two users are pre-registered:
> - **Username**: `alice`, **Password**: `alice123`
> - **Username**: `bob`, **Password**: `bob456`


### 3. Messaging
- **Add Contact**: Use the "Add Contact" button to start a chat with another registered user.
- **Send Messages**: Select a contact and type your message in the text field.

## Security Architecture

1. **Authentication**: Uses a challenge-response style login where the plaintext password is never transmitted.
2. **Handshake**: A Diffie-Hellman exchange happens at the start of every connection to establish a shared symmetric key for DES.
3. **Session Keys**: Individual session keys for chat partners are exchanged via RSA encryption and stored locally for future messages.
4. **Data Isolation**: Each client user has their own SQLite database stored in `client/dbs/client_<username>.db`.

## Development & Testing

Run the full test suite using:
```bash
python3 -m unittest discover tests
```
