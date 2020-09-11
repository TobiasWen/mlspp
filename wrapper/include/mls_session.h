#pragma once
#include <stdbool.h>
#include "mls_common.h"
#include "mls_crypto.h"
#include "mls_core_types.h"
#ifdef __cplusplus
#include "mls/session.h"
extern "C" {
#endif
struct mls_init_info {
    uint8_t *init_secret;
    size_t init_secret_size;
    struct mls_signature_private_key sig_priv;
    struct mls_key_package key_package;
};

struct mls_session {
    void *state;
    uint64_t current_epoch;
    bool encrypted_handshake;
};

struct mls_session_welcome_tuple {
    void *session;
    void *welcome;
};


struct mls_init_info mls_temp_init_info(mls_cipher_suite suite, struct mls_signature_private_key identity_priv, struct mls_credential credential);
struct mls_key_package mls_fresh_key_package(mls_cipher_suite suite, struct mls_signature_private_key identity_priv, struct mls_credential credential, struct mls_init_info *infos, int current_index);
struct mls_session_welcome_tuple mls_session_start(struct mls_bytes group_id, struct mls_init_info *my_info, size_t my_init_info_size, struct mls_key_package *key_packages, size_t key_packages_size, struct mls_bytes random_bytes);
#ifdef __cplusplus
mls::Session::InitInfo mls_to_init_info(struct mls_init_info info);
}
#endif