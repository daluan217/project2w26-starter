### Implementation Guide

Here's how the functions declared in `libsecurity.h` map to your TODOs:

#### Key Management

- **Generate Keys:** Call `generate_private_key()` then `derive_public_key()`. This populates the global `public_key` buffer (your ephemeral key).
- **Loading Peer Keys:** When you receive a public key from the network (either in a Hello message or inside a Certificate), use `load_peer_public_key(buf, len)` to load it into the OpenSSL context.
- **Loading Private Keys:** Use `load_private_key("filename")`.
    
    - _Tip:_ The Server needs to switch between keys. It normally uses its **Ephemeral Key** (for deriving secrets), but temporarily needs its **Identity Key** (from `server_key.bin`) to sign the handshake. Use `get_private_key()` and `set_private_key()` to save/restore the ephemeral key before/after loading the identity key.

#### Handshake Logic

- **Nonces:** Use `generate_nonce(buf, size)`. You must store these in `client_nonce` and `server_nonce` arrays for key derivation later.
- **Signatures (Server):** Use `sign(sig_buf, data, len)`.
    - _Input Data:_ You must verify the signature over the **Serialized TLVs**. Create a temporary buffer, serialize the Client Hello TLV, then append the serialized Server Nonce TLV, then the serialized Ephemeral Key TLV. Sign this combined buffer.
- **Signatures (Client):** Use `verify(sig_buf, sig_len, data, data_len, key)`.
    - For the **Certificate**, the `key` is `ec_ca_public_key`.
    - For the **Handshake**, the `key` is the Server's Identity Key (found inside the Cert). Note that `libsecurity`'s `verify` function allows passing a specific authority key.

#### Encryption & Data

- **Deriving Secrets:**
    
    1. Ensure you have loaded the peer's ephemeral public key (`load_peer_public_key`).
    2. Call `derive_secret()`.
    3. Construct the 64-byte salt (`client_nonce` concatenated with `server_nonce`).
    4. Call `derive_keys(salt, 64)`.
        
- **Sending Data:**
    1. Read input: `input_io(buffer, max_len)`.
    2. Encrypt: `encrypt_data(iv_buf, cipher_buf, plain_buf, plain_len)`. This fills the IV and Ciphertext buffers for you.
    3. MAC: `hmac(digest, data, len)`. The data must be `Serialized(IV_TLV) + Serialized(Ciphertext_TLV)`.
        
- **Receiving Data:**
    
    1. MAC Check: Re-serialize the received IV and Ciphertext TLVs locally. Run `hmac()` on them. Compare the result with the received MAC.
    2. Decrypt: `decrypt_cipher(plain_buf, cipher_buf, len, iv)`.
    3. Write output: `output_io(plain_buf, len)`.
