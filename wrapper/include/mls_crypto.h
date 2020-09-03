#pragma once
#include "mls_common.h"
#include "stddef.h"
#ifdef __cplusplus
#include "mls/crypto.h"
extern "C" {
#endif
struct mls_signature_private_key {
    mls_cipher_suite cipher_suite;
    mls_signature_scheme signature_scheme;
    uint8_t *data;
    uint32_t data_size;
    uint8_t *pub_data;
    uint32_t pub_data_size;
};

struct mls_signature_public_key {
    mls_signature_scheme signature_scheme;
    uint8_t *data;
    uint32_t data_size;
};

struct mls_HPKE_public_key {
    uint8_t *data;
    size_t data_size;
};

struct mls_HPKE_private_key {
    uint8_t *data;
    size_t data_size;
    uint8_t *pub_data;
    size_t pub_data_size;
};

struct mls_signature_private_key mls_generate_mls_signature_private_key(mls_cipher_suite suite);
struct mls_signature_public_key mls_get_signature_public_key_from_private_key(struct mls_signature_private_key private_key);
struct mls_HPKE_private_key mls_derive_HPKE_private_key(mls_cipher_suite suite, uint8_t *secret, size_t secret_size);

#ifdef __cplusplus
}
// Signature Private/Public Key type conversions
mls_signature_private_key mls_convert_from_signature_private_key(mls::SignaturePrivateKey private_key);
mls::SignaturePrivateKey mls_convert_to_signature_private_key(mls_signature_private_key private_key);
mls_signature_public_key mls_convert_from_signature_public_key(mls::SignaturePublicKey public_key);
mls::SignaturePublicKey mls_convert_to_signature_public_key(mls_signature_public_key public_key);

// HPKE Private/Public Key type conversions
mls_HPKE_private_key mls_convert_from_HPKE_private_key(mls::HPKEPrivateKey private_key);
mls::HPKEPrivateKey mls_convert_to_HPKE_private_key(mls_HPKE_private_key private_key);
mls_HPKE_public_key mls_convert_from_HPKE_public_key(mls::HPKEPublicKey public_key);
mls::HPKEPublicKey mls_convert_to_HPKE_public_key(mls_HPKE_public_key public_key);
#endif