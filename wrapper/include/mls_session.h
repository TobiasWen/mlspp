#pragma once
#include "mls_common.h"
#include "mls_crypto.h"
#include "mls_core_types.h"
#ifdef __cplusplus
extern "C" {
#endif
struct mls_init_info {
    uint8_t *init_secret;
    size_t init_secret_size;
    struct mls_signature_private_key sig_priv;
    struct mls_key_package key_package;
};

struct mls_init_info mls_temp_init_info(mls_cipher_suite suite, struct mls_signature_private_key identity_priv, struct mls_credential credential);
struct mls_key_package mls_fresh_key_package(mls_cipher_suite suite, struct mls_signature_private_key identity_priv, struct mls_credential credential, struct mls_init_info *infos, int current_index);
#ifdef __cplusplus
}
#endif