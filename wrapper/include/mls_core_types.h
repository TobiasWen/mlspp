#pragma once
#include "mls_common.h"
#include "mls_crypto.h"
#include "mls_credential.h"
#ifdef __cplusplus
extern "C" {
#endif
typedef enum {
    mls10 = 0xFF
} mls_protocol_version;

typedef enum {
    supported_version = 1,
    supported_cipher_suites = 2,
    lifetime = 3,
    key_id = 4,
    parent_hash = 5
} mls_extension_type;

struct mls_extension {
    mls_extension_type type;
    uint8_t *data;
    uint32_t data_size;
};

struct mls_extension_list {
    mls_extension *extensions;
    size_t extensions_size;
};

struct mls_key_package {
    mls_protocol_version version;
    mls_cipher_suite cipher_suite;
    mls_HPKE_public_key init_key;
    mls_credential credential;
    mls_extension_list extensions;
    uint8_t *signature;
    uint32_t signature_size;
};

#ifdef __cplusplus

}
#endif