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
    uint8_t *identity;
    uint32_t identity_size;
    struct mls_signature_public_key public_key;
    mls_credential_type type;
};

struct mls_credential {
    struct mls_basic_credential cred;
};

struct mls_credential mls_create_basic_credential(uint8_t *identity, uint32_t identity_size, struct mls_signature_public_key public_key);
#ifdef __cplusplus
struct mls_credential mls_from_credential(mls::Credential cred);
}
#endif