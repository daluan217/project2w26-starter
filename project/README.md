# CS 118 Winter 26 Project 2 — Secure Transport Layer

## Overview

This project implements a secure transport layer on top of a reliable TCP connection, providing **authenticity**, **privacy**, and **integrity** between a client and server using a custom TLS-like handshake protocol.

## Implementation

All work is in `src/security.c`. The implementation covers:

### Handshake

**Client Hello (`CLIENT_CLIENT_HELLO_SEND`):**  
The client generates an ephemeral ECDH keypair and a 32-byte random nonce, then sends a `CLIENT_HELLO` TLV containing the protocol version, nonce, and ephemeral public key.

**Server Hello (`SERVER_SERVER_HELLO_SEND`):**  
The server generates its own nonce and ephemeral keypair, then sends a `SERVER_HELLO` TLV containing its nonce, certificate, ephemeral public key, and a handshake signature. The signature is computed over `Serialized(ClientHello) + Serialized(ServerNonce) + Serialized(ServerEphemeralKey)` using the server's identity private key (`server_key.bin`). The server then derives session keys and enters `DATA_STATE`.

**Client Verification (`CLIENT_SERVER_HELLO_AWAIT`):**  
The client validates the server's certificate (CA signature, lifetime window, DNS name match), then verifies the handshake signature using the server's identity public key found inside the certificate. If all checks pass, it derives session keys and enters `DATA_STATE`.

### Session Key Derivation

Both sides compute:
- **Secret**: ECDH(my ephemeral private key, peer ephemeral public key)
- **Salt**: `client_nonce || server_nonce` (64 bytes)
- **Keys**: HKDF-SHA256 with info strings `"enc"` (AES key) and `"mac"` (HMAC key)

### Data Transmission (`DATA_STATE`)

**Sending**: plaintext → AES-256-CBC encrypt → HMAC-SHA256 over `Serialized(IV) + Serialized(Ciphertext)` → package as `DATA` TLV (IV + MAC + Ciphertext).

**Receiving**: extract IV/MAC/Ciphertext → recompute and verify HMAC (exit 5 on mismatch) → AES-256-CBC decrypt → write plaintext to stdout.

### Error Handling

| Exit Code | Condition |
|-----------|-----------|
| `1` | Invalid CA signature on certificate, or certificate expired |
| `2` | DNS name in certificate does not match target hostname |
| `3` | Invalid handshake signature in Server Hello |
| `5` | HMAC verification failure on a data message |
| `6` | Malformed TLV, missing required fields, or wrong protocol version |