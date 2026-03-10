#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#include "libsecurity.h"
#include "io.h"
#include "consts.h"

int state_sec = 0;
char *hostname = NULL;
EVP_PKEY *priv_key = NULL;
tlv *client_hello = NULL;
tlv *server_hello = NULL;
bool inc_mac = false;

/* Buffers to hold nonces for key derivation salt */
static uint8_t client_nonce[NONCE_SIZE];
static uint8_t server_nonce[NONCE_SIZE];

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

static uint64_t read_be_uint(const uint8_t* bytes, size_t nbytes) {
    uint64_t result = 0;
    for (size_t i = 0; i < nbytes; i++) {
        result = (result << 8) | bytes[i];
    }
    return result;
}

static bool parse_lifetime_window(const tlv* life, uint64_t* start_ts, uint64_t* end_ts) {
    if (life == NULL || start_ts == NULL || end_ts == NULL) return false;
    if (life->val == NULL || life->length != 16) return false;

    *start_ts = read_be_uint(life->val,     8);
    *end_ts   = read_be_uint(life->val + 8, 8);

    if (*end_ts < *start_ts) return false;
    return true;
}

static void enforce_lifetime_valid(const tlv* life) {
    uint64_t not_before, not_after;

    if (!parse_lifetime_window(life, &not_before, &not_after)) {
        exit(6); /* malformed */
    }

    time_t now_t = time(NULL);
    if (now_t == (time_t)-1) exit(6);

    uint64_t now = (uint64_t)now_t;

    if (now < not_before || now > not_after) {
        exit(1); /* expired / not yet valid */
    }
}

/* ------------------------------------------------------------------ */
/* init_sec                                                            */
/* ------------------------------------------------------------------ */

void init_sec(int initial_state, char* peer_host, bool bad_mac) {
    state_sec = initial_state;
    hostname  = peer_host;
    inc_mac   = bad_mac;
    init_io();

    if (initial_state == CLIENT_CLIENT_HELLO_SEND) {
        /* Client: load CA public key, generate ephemeral keypair */
        load_ca_public_key("ca_public_key.bin");
        generate_private_key();
        derive_public_key();
    } else {
        /* Server: load identity key + certificate, generate ephemeral keypair */
        load_certificate("server_cert.bin");
        generate_private_key();
        derive_public_key();
    }
}

/* ------------------------------------------------------------------ */
/* input_sec  (sending side)                                           */
/* ------------------------------------------------------------------ */

ssize_t input_sec(uint8_t* out_buf, size_t out_cap) {
    switch (state_sec) {

    /* -------- CLIENT HELLO ---------------------------------------- */
    case CLIENT_CLIENT_HELLO_SEND: {
        print("SEND CLIENT HELLO");

        /* Version TLV */
        tlv* ver = create_tlv(VERSION_TAG);
        uint8_t ver_val = PROTOCOL_VERSION;
        add_val(ver, &ver_val, 1);

        /* Nonce TLV */
        generate_nonce(client_nonce, NONCE_SIZE);
        tlv* nonce_tlv = create_tlv(NONCE);
        add_val(nonce_tlv, client_nonce, NONCE_SIZE);

        /* Public Key TLV */
        tlv* pub = create_tlv(PUBLIC_KEY);
        add_val(pub, public_key, pub_key_size);

        /* CLIENT_HELLO container */
        tlv* ch = create_tlv(CLIENT_HELLO);
        add_tlv(ch, ver);
        add_tlv(ch, nonce_tlv);
        add_tlv(ch, pub);

        /* Save for later signature verification */
        client_hello = ch;

        uint16_t len = serialize_tlv(out_buf, ch);

        /* Do NOT free client_hello — we need it later */
        state_sec = CLIENT_SERVER_HELLO_AWAIT;
        return (ssize_t)len;
    }

    /* -------- SERVER HELLO ---------------------------------------- */
    case SERVER_SERVER_HELLO_SEND: {
        print("SEND SERVER HELLO");

        /* Server nonce */
        generate_nonce(server_nonce, NONCE_SIZE);
        tlv* s_nonce = create_tlv(NONCE);
        add_val(s_nonce, server_nonce, NONCE_SIZE);

        /* Certificate TLV (raw bytes loaded from file) */
        tlv* cert_tlv = deserialize_tlv(certificate, (uint16_t)cert_size);
        if (cert_tlv == NULL) exit(6);

        /* Server ephemeral public key TLV */
        tlv* s_pub = create_tlv(PUBLIC_KEY);
        add_val(s_pub, public_key, pub_key_size);

        /* Build the data to sign:
           Serialized(client_hello) + Serialized(server_nonce) + Serialized(server_pub_key) */
        uint8_t sign_buf[4096];
        uint16_t sign_off = 0;
        sign_off += serialize_tlv(sign_buf + sign_off, client_hello);
        sign_off += serialize_tlv(sign_buf + sign_off, s_nonce);
        sign_off += serialize_tlv(sign_buf + sign_off, s_pub);

        /* Sign with the server's identity key.
           The server's identity key was loaded during init but then overwritten by
           generate_private_key(). We need to reload it, sign, then restore. */
        EVP_PKEY* ephemeral = get_private_key();
        load_private_key("server_key.bin");

        uint8_t sig_bytes[256];
        size_t sig_len = sign(sig_bytes, sign_buf, sign_off);

        /* Restore ephemeral key for ECDH later */
        set_private_key(ephemeral);

        tlv* hs_sig = create_tlv(HANDSHAKE_SIGNATURE);
        add_val(hs_sig, sig_bytes, sig_len);

        /* SERVER_HELLO container */
        tlv* sh = create_tlv(SERVER_HELLO);
        add_tlv(sh, s_nonce);
        add_tlv(sh, cert_tlv);
        add_tlv(sh, s_pub);
        add_tlv(sh, hs_sig);

        uint16_t len = serialize_tlv(out_buf, sh);
        free_tlv(sh);

        /* Derive session keys: secret = ECDH(ephem_priv, client_ephem_pub) */
        derive_secret();
        uint8_t salt[NONCE_SIZE * 2];
        memcpy(salt,             client_nonce, NONCE_SIZE);
        memcpy(salt + NONCE_SIZE, server_nonce, NONCE_SIZE);
        derive_keys(salt, sizeof(salt));

        state_sec = DATA_STATE;
        return (ssize_t)len;
    }

    /* -------- DATA STATE ------------------------------------------ */
    case DATA_STATE: {
        uint8_t plain[4096];
        ssize_t plain_len = input_io(plain, sizeof(plain));
        if (plain_len <= 0) return 0;

        /* Encrypt */
        uint8_t iv_bytes[IV_SIZE];
        uint8_t cipher_bytes[4096 + 16]; /* AES padding */
        size_t cipher_len = encrypt_data(iv_bytes, cipher_bytes, plain, (size_t)plain_len);

        /* Build IV and Ciphertext TLVs */
        tlv* iv_tlv = create_tlv(IV);
        add_val(iv_tlv, iv_bytes, IV_SIZE);

        tlv* ct_tlv = create_tlv(CIPHERTEXT);
        add_val(ct_tlv, cipher_bytes, (uint16_t)cipher_len);

        /* MAC over Serialized(IV) + Serialized(Ciphertext) */
        uint8_t mac_input[4096 + 64];
        uint16_t mac_off = 0;
        mac_off += serialize_tlv(mac_input + mac_off, iv_tlv);
        mac_off += serialize_tlv(mac_input + mac_off, ct_tlv);

        uint8_t mac_bytes[MAC_SIZE];
        hmac(mac_bytes, mac_input, mac_off);

        /* Optionally corrupt MAC for testing */
        if (inc_mac) mac_bytes[0] ^= 0xFF;

        tlv* mac_tlv = create_tlv(MAC);
        add_val(mac_tlv, mac_bytes, MAC_SIZE);

        /* DATA container: IV, MAC, Ciphertext */
        tlv* data_tlv = create_tlv(DATA);
        add_tlv(data_tlv, iv_tlv);
        add_tlv(data_tlv, mac_tlv);
        add_tlv(data_tlv, ct_tlv);

        uint16_t len = serialize_tlv(out_buf, data_tlv);
        free_tlv(data_tlv);

        return (ssize_t)len;
    }

    default:
        return 0;
    }
}

/* ------------------------------------------------------------------ */
/* output_sec  (receiving side)                                        */
/* ------------------------------------------------------------------ */

void output_sec(uint8_t* in_buf, size_t in_len) {
    switch (state_sec) {

    /* -------- AWAIT CLIENT HELLO ---------------------------------- */
    case SERVER_CLIENT_HELLO_AWAIT: {
        print("RECV CLIENT HELLO");

        tlv* ch = deserialize_tlv(in_buf, (uint16_t)in_len);
        if (ch == NULL || ch->type != CLIENT_HELLO) exit(6);

        /* Validate protocol version */
        tlv* ver = get_tlv(ch, VERSION_TAG);
        if (ver == NULL || ver->length != 1 || ver->val[0] != PROTOCOL_VERSION) exit(6);

        /* Extract nonce */
        tlv* c_nonce = get_tlv(ch, NONCE);
        if (c_nonce == NULL || c_nonce->length != NONCE_SIZE) exit(6);
        memcpy(client_nonce, c_nonce->val, NONCE_SIZE);

        /* Extract client ephemeral public key */
        tlv* c_pub = get_tlv(ch, PUBLIC_KEY);
        if (c_pub == NULL) exit(6);
        load_peer_public_key(c_pub->val, c_pub->length);

        /* Save full client_hello TLV for signing in SERVER_SERVER_HELLO_SEND */
        client_hello = ch; /* ownership transferred; freed after server hello sent */

        state_sec = SERVER_SERVER_HELLO_SEND;
        break;
    }

    /* -------- AWAIT SERVER HELLO ---------------------------------- */
    case CLIENT_SERVER_HELLO_AWAIT: {
        print("RECV SERVER HELLO");

        tlv* sh = deserialize_tlv(in_buf, (uint16_t)in_len);
        if (sh == NULL || sh->type != SERVER_HELLO) exit(6);

        /* Extract server nonce */
        tlv* s_nonce = get_tlv(sh, NONCE);
        if (s_nonce == NULL || s_nonce->length != NONCE_SIZE) exit(6);
        memcpy(server_nonce, s_nonce->val, NONCE_SIZE);

        /* Extract and validate certificate */
        tlv* cert = get_tlv(sh, CERTIFICATE);
        if (cert == NULL) exit(6);

        tlv* dns  = get_tlv(cert, DNS_NAME);
        tlv* cpub = get_tlv(cert, PUBLIC_KEY);  /* server identity public key */
        tlv* life = get_tlv(cert, LIFETIME);
        tlv* csig = get_tlv(cert, SIGNATURE);
        if (dns == NULL || cpub == NULL || life == NULL || csig == NULL) exit(6);

        /* Verify certificate signature (CA signs dns + pubkey + lifetime) */
        uint8_t cert_data[4096];
        uint16_t cert_off = 0;

        tlv* dns_tmp = create_tlv(DNS_NAME);
        add_val(dns_tmp, dns->val, dns->length);
        cert_off += serialize_tlv(cert_data + cert_off, dns_tmp);
        free_tlv(dns_tmp);

        tlv* cpub_tmp = create_tlv(PUBLIC_KEY);
        add_val(cpub_tmp, cpub->val, cpub->length);
        cert_off += serialize_tlv(cert_data + cert_off, cpub_tmp);
        free_tlv(cpub_tmp);

        tlv* life_tmp = create_tlv(LIFETIME);
        add_val(life_tmp, life->val, life->length);
        cert_off += serialize_tlv(cert_data + cert_off, life_tmp);
        free_tlv(life_tmp);

        int cert_ok = verify(csig->val, csig->length, cert_data, cert_off, ec_ca_public_key);
        if (cert_ok != 1) exit(1);

        /* Verify certificate lifetime */
        enforce_lifetime_valid(life);

        /* Verify hostname (DNS name in cert must match target hostname) */
        /* dns->val includes the null terminator written by gen_cert */
        if (hostname == NULL || dns->val == NULL) exit(2);
        if (strcmp((char*)dns->val, hostname) != 0) exit(2);

        /* Load server identity public key to verify handshake signature */
        load_peer_public_key(cpub->val, cpub->length);
        EVP_PKEY* server_id_key = ec_peer_public_key;

        /* Extract server ephemeral public key */
        tlv* s_pub = get_tlv(sh, PUBLIC_KEY);
        if (s_pub == NULL) exit(6);

        /* Verify handshake signature over:
           Serialized(client_hello) + Serialized(server_nonce_tlv) + Serialized(server_ephem_pub_tlv) */
        tlv* hs_sig = get_tlv(sh, HANDSHAKE_SIGNATURE);
        if (hs_sig == NULL) exit(6);

        uint8_t hs_data[8192];
        uint16_t hs_off = 0;
        hs_off += serialize_tlv(hs_data + hs_off, client_hello);

        tlv* sn_tmp = create_tlv(NONCE);
        add_val(sn_tmp, server_nonce, NONCE_SIZE);
        hs_off += serialize_tlv(hs_data + hs_off, sn_tmp);
        free_tlv(sn_tmp);

        tlv* spub_tmp = create_tlv(PUBLIC_KEY);
        add_val(spub_tmp, s_pub->val, s_pub->length);
        hs_off += serialize_tlv(hs_data + hs_off, spub_tmp);
        free_tlv(spub_tmp);

        int hs_ok = verify(hs_sig->val, hs_sig->length, hs_data, hs_off, server_id_key);
        if (hs_ok != 1) exit(3);

        /* Load server ephemeral key for ECDH */
        load_peer_public_key(s_pub->val, s_pub->length);

        /* Derive session keys */
        derive_secret();
        uint8_t salt[NONCE_SIZE * 2];
        memcpy(salt,              client_nonce, NONCE_SIZE);
        memcpy(salt + NONCE_SIZE, server_nonce, NONCE_SIZE);
        derive_keys(salt, sizeof(salt));

        free_tlv(sh);
        free_tlv(client_hello);
        client_hello = NULL;

        state_sec = DATA_STATE;
        break;
    }

    /* -------- DATA STATE ------------------------------------------ */
    case DATA_STATE: {
        tlv* data = deserialize_tlv(in_buf, (uint16_t)in_len);
        if (data == NULL || data->type != DATA) exit(6);

        tlv* iv_tlv  = get_tlv(data, IV);
        tlv* mac_tlv = get_tlv(data, MAC);
        tlv* ct_tlv  = get_tlv(data, CIPHERTEXT);
        if (iv_tlv == NULL || mac_tlv == NULL || ct_tlv == NULL) exit(6);

        /* Re-compute MAC over Serialized(IV) + Serialized(Ciphertext) */
        uint8_t mac_input[8192];
        uint16_t mac_off = 0;
        mac_off += serialize_tlv(mac_input + mac_off, iv_tlv);
        mac_off += serialize_tlv(mac_input + mac_off, ct_tlv);

        uint8_t expected_mac[MAC_SIZE];
        hmac(expected_mac, mac_input, mac_off);

        if (mac_tlv->length != MAC_SIZE ||
            memcmp(expected_mac, mac_tlv->val, MAC_SIZE) != 0) {
            exit(5);
        }

        /* Decrypt */
        uint8_t plain[8192];
        size_t plain_len = decrypt_cipher(plain, ct_tlv->val, ct_tlv->length, iv_tlv->val);

        output_io(plain, plain_len);
        free_tlv(data);
        break;
    }

    default:
        break;
    }
}