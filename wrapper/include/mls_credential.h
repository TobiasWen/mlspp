#pragma once
#include "mls_common.h"
#include "mls_crypto.h"
#include "mls_core_types.h"
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

bool mls_create_basic_credential(struct mls_credential *target, mls_bytes *identity, struct mls_signature_public_key *public_key);
#ifdef __cplusplus
bool mls_from_credential(struct mls_credential *target, mls::Credential *src);
bool mls_to_credential(mls::Credential *target, struct mls_credential *src);
}
#endif