#include "consts.h"
#include "libsecurity.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <time.h>

static void write_be_uint(uint8_t* buf, uint64_t value, size_t len) {
    for (size_t i = 0; i < len; i++) {
        buf[len - 1 - i] = (uint8_t) (value & 0xFF);
        value >>= 8;
    }
}

int main(int argc, char** argv) {
    if (argc < 5) {
        fprintf(stderr,
                "Usage: %s server_private_key ca_private_key dns_name output [not_before not_after]\n",
                argv[0]);
        return 1;
    }

    load_private_key(argv[1]);
    derive_public_key();
    load_private_key(argv[2]);

    time_t now = time(NULL);
    if (now == (time_t) -1) {
        fprintf(stderr, "Error: failed to read system time\n");
        return 1;
    }

    uint64_t not_before = (uint64_t) now;
    uint64_t not_after = not_before + 31536000ULL; // default: 1 year validity

    if (argc >= 6) {
        not_before = strtoull(argv[5], NULL, 10);
    }

    if (argc >= 7) {
        not_after = strtoull(argv[6], NULL, 10);
    }

    if (not_after < not_before) {
        fprintf(stderr, "Error: certificate lifetime invalid (not_after < not_before)\n");
        return 1;
    }

    tlv* cert = create_tlv(CERTIFICATE);

    tlv* dn = create_tlv(DNS_NAME);
    add_val(dn, (uint8_t*) argv[3], strlen(argv[3]) + 1);

    tlv* pub_key = create_tlv(PUBLIC_KEY);
    add_val(pub_key, public_key, pub_key_size);

    tlv* lifetime = create_tlv(LIFETIME);
    uint8_t lifetime_buf[16];
    write_be_uint(lifetime_buf, not_before, 8);
    write_be_uint(lifetime_buf + 8, not_after, 8);
    add_val(lifetime, lifetime_buf, sizeof lifetime_buf);

    tlv* s = create_tlv(SIGNATURE);
    uint8_t b[1000];
    uint16_t offset = 0;
    offset += serialize_tlv(b + offset, dn);
    offset += serialize_tlv(b + offset, pub_key);
    offset += serialize_tlv(b + offset, lifetime);
    uint8_t sig[255];
    size_t sig_size = sign(sig, b, offset);
    add_val(s, sig, sig_size);

    add_tlv(cert, dn);
    add_tlv(cert, pub_key);
    add_tlv(cert, lifetime);
    add_tlv(cert, s);

    uint16_t len = serialize_tlv(b, cert);

    FILE* fp = fopen(argv[4], "w");
    fwrite(b, len, 1, fp);
    fclose(fp);

    /* print_tlv_bytes(b, len); */
    /* tlv* cert2 = deserialize_tlv(b, len); */
    /* uint16_t len2 = serialize_tlv(b, cert2); */
    /* print_tlv_bytes(b, len2); */

    return 0;
}
