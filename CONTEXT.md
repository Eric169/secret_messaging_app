# Project Context: Secret Messaging App

## Overview
This is a secure messaging application built with a Client-Server architecture. The server acts as a relay for messages between users. 

## Technical Stack
- **Language**: Python
- **Network**: TCP Sockets
- **Database**: SQLite3 (.db files)

## Critical Constraints
- **NO Cryptographic Libraries**: The project uses custom, manual implementations of all cryptographic algorithms (e.g., *no Pycryptodome*). The built-in `secrets` library is only used for random number generation (`getrandbits`).

## Cryptographic Design
### 1. Client-Server Communication (Hybrid Encryption)
- **Algorithms**: Diffie-Hellman + RSA
- **Key Sizes**: 2048-bit for both RSA and DH.
- **Workflow**:
  - The connection avoids Man-In-The-Middle (MITM) attacks by having the server sign the DH key exchange with its RSA private key. The server's RSA public key is known *a priori* to the clients (no certificates).
  - DH parameters $p$ and $g$ are fixed for the exchange to save computation time.
  - After the shared key is established, communication is encrypted symmetrically (e.g., using DES).

### 2. Client-Client Communication
- **Algorithm**: DES (chosen for simplicity of manual implementation over security).
- **Workflow**: 
  - To communicate, Client A requests Client B's public key from the server (`GET_PUBLIC_KEY`).
  - Client A generates a symmetric session key, encrypts it with Client B's public key, and sends it (`SEND_SESSION_KEY`).
  - Messages are then sent symmetrically encrypted (`SEND_MESSAGE`) using DES.

### 3. Prime Number Generation
- **Algorithm**: Fermat's Probabilistic Primality Test
- **Implementation Details**: Uses $k=3$ iterations to guarantee sufficient correctness for ~600-digit (2048-bit) numbers.

## Application Architecture & Protocol
- **Message Format**: `TYPE | LENGTH | PAYLOAD`
- **Main Actions**: `REGISTER`, `LOGIN`, `SEND_MESSAGE`, `GET_PUBLIC_KEY`, `GET_MESSAGES`

## Database Architecture
- **Server DB**: Stores users (`id`, password hash, public sessions keys) and pending messages. The server only sees *encrypted* payload data and cannot read messages. It clears messages once an end-client fetches them via `GET_MESSAGES`.
- **Client DB**: Stores the message history (`id`, plaintext messages) and cryptographic keys. Messages are stored in plaintext locally because if the filesystem is compromised, the local private keys are also compromised, making local encryption redundant. 
