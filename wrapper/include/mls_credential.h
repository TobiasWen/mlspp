#pragma once
#include "mls_common.h"
#include "mls_crypto.h"
#ifdef __cplusplus
#include "mls/credential.h"
extern "C" {
#endif
typedef enum
{
    basic = 0,
    x509 = 1
} mls_credential_type;

struct mls_basic_credential {
    struct mls_bytes identity;
    struct mls_signature_public_key public_key;
    mls_credential_type type;
};

struct mls_credential {
    struct mls_basic_credential cred;
};

bool mls_credential_allocate(struct mls_credential *target, struct mls_bytes *identity, size_t key_size);
bool mls_credential_instantiate(struct mls_credential *target, struct mls_bytes *identity, struct mls_signature_public_key *public_key, size_t key_size);
bool mls_credential_destroy(struct mls_credential *target);
bool mls_create_basic_credential(struct mls_credential *target, struct mls_bytes *identity, struct mls_signature_public_key *public_key);
#ifdef __cplusplus
bool mls_from_credential(struct mls_credential *target, mls::Credential *src);
bool mls_from_basic_credential(struct mls_basic_credential *target, mls::BasicCredential *src);
bool mls_to_credential(mls::Credential *target, struct mls_credential *src);
bool mls_to_basic_credential(mls::BasicCredential *target, struct mls_basic_credential *src);
bool mls_copy_credential(mls_credential *target, struct mls_credential *src);
}
#endif