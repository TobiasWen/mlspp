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
    struct mls_bytes init_secret;
    struct mls_signature_private_key sig_priv;
    struct mls_key_package key_package;
};

struct mls_session {
    void *data;
    size_t size;
    size_t size_reserved;
};

struct mls_welcome {
    struct mls_bytes bytes;
    size_t size_reserved;
};

struct mls_session_welcome_tuple {
    struct mls_session session;
    struct mls_welcome welcome;
};

bool mls_temp_init_info_instantiate(struct mls_init_info *target, mls_cipher_suite suite, struct mls_signature_private_key *identity_priv, struct mls_credential *credential, size_t size);
bool mls_temp_init_info_destroy(struct mls_init_info *target);
bool mls_temp_init_info(struct mls_init_info *target, mls_cipher_suite suite, struct mls_signature_private_key *identity_priv, struct mls_credential *credential, size_t size);
bool mls_fresh_key_package_instantiate(struct mls_key_package *target, mls_cipher_suite suite, struct mls_signature_private_key *identity_priv, struct mls_credential *credential, struct mls_init_info *infos, const int *current_index,  size_t size);
bool mls_fresh_key_package_destroy(struct mls_key_package *target);
bool mls_fresh_key_package(struct mls_key_package *target, mls_cipher_suite suite, struct mls_signature_private_key *identity_priv, struct mls_credential *credential, struct mls_init_info *infos, int *current_index,  size_t size);
bool mls_session_start(struct mls_session_welcome_tuple *target, struct mls_bytes *group_id, struct mls_init_info *my_info, size_t my_init_info_size, struct mls_key_package *key_packages, size_t key_packages_size, struct mls_bytes *random_bytes);
bool mls_session_join(struct mls_session *target, struct mls_init_info *infos, size_t infos_size, struct mls_session_welcome_tuple *session_welcome);
bool mls_copy_init_info(struct mls_init_info *target, struct mls_init_info *src);
#ifdef __cplusplus
bool mls_to_init_info(mls::Session::InitInfo *target, struct mls_init_info *info);
}
#endif