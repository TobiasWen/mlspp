#pragma once
#include <stddef.h>
#include "mls_common.h"
#ifdef __cplusplus
#include "mls/crypto.h"
extern "C" {
#endif
struct mls_signature_public_key {
    mls_signature_scheme signature_scheme;
    struct mls_bytes data;
};

struct mls_signature_private_key {
    mls_cipher_suite cipher_suite;
    mls_signature_scheme signature_scheme;
    struct mls_bytes data;
    struct mls_signature_public_key public_key;
};

struct mls_HPKE_public_key {
    struct mls_bytes data;
};

struct mls_HPKE_private_key {
    struct mls_bytes data;
    struct mls_HPKE_public_key public_key;
};

bool mls_signature_private_key_instantiate(struct mls_signature_private_key *target, mls_cipher_suite suite, size_t size);
bool mls_signature_private_key_destroy(struct mls_signature_private_key *target);
bool mls_signature_public_key_instantiate(struct mls_signature_public_key *target, struct mls_bytes *data, mls_signature_scheme scheme);
bool mls_signature_public_key_destroy(struct mls_signature_public_key *target);
bool mls_generate_mls_signature_private_key(struct mls_signature_private_key *target, mls_cipher_suite suite);
//bool mls_get_signature_public_key_from_private_key(struct mls_signature_public_key *target, struct mls_signature_private_key *private_key);
bool mls_hpke_private_key_allocate(struct mls_HPKE_private_key *target, size_t key_size);
bool mls_HPKE_private_key_destroy(struct mls_HPKE_private_key *target);
bool mls_hpke_public_key_allocate(struct mls_HPKE_public_key *target, size_t key_size);
bool mls_hpke_public_key_destroy(struct mls_HPKE_public_key *target);
bool mls_derive_HPKE_private_key(struct mls_HPKE_private_key *target, mls_cipher_suite suite, struct mls_bytes *secret);

#ifdef __cplusplus
}
// Signature Private/Public Key type conversions
bool mls_convert_from_signature_private_key(mls_signature_private_key *target, mls::SignaturePrivateKey *src);
bool mls_convert_to_signature_private_key(mls::SignaturePrivateKey *target, mls_signature_private_key *src);
bool mls_convert_from_signature_public_key(mls_signature_public_key *target, mls::SignaturePublicKey *src);
bool mls_convert_to_signature_public_key(mls::SignaturePublicKey *target, mls_signature_public_key *src);

// HPKE Private/Public Key type conversions
bool mls_convert_from_HPKE_private_key(mls_HPKE_private_key *target, mls::HPKEPrivateKey *src);
bool mls_convert_to_HPKE_private_key(mls::HPKEPrivateKey *target, mls_HPKE_private_key *src);
bool mls_convert_from_HPKE_public_key(mls_HPKE_public_key *target, mls::HPKEPublicKey *src);
bool mls_convert_to_HPKE_public_key(mls::HPKEPublicKey *target, mls_HPKE_public_key *src);
#endif