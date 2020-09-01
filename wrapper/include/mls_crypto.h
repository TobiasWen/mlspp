#pragma once
#include "mls_common.h"
#ifdef __cplusplus
#include "mls/crypto.h"
extern "C" {
#endif
struct mls_signature_private_key {
    mls_cipher_suite cipher_suite;
    mls_signature_scheme signature_scheme;
    uint8_t *data; // Array of uint8_t
    uint32_t data_size;
    uint8_t *pub_data; // Array of uint8_t
    uint32_t pub_data_size;
};

struct mls_signature_public_key {
    mls_signature_scheme signature_scheme;
    uint8_t *data;
    uint32_t data_size;
};

struct mls_signature_private_key mls_generate_mls_signature_private_key(mls_cipher_suite suite);
struct mls_signature_public_key mls_get_signature_public_key_from_private_key(struct mls_signature_private_key private_key);

#ifdef __cplusplus
}
mls_signature_private_key convert_from_signature_private_key(const mls::SignaturePrivateKey private_key);
mls::SignaturePrivateKey convert_to_signature_private_key(const mls_signature_private_key private_key);
mls::SignaturePublicKey convert_to_signature_public_key(const mls_signature_public_key public_key);
mls_signature_public_key convert_from_signature_public_key(const mls::SignaturePublicKey public_key);
#endif