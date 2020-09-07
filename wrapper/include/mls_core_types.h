#pragma once

#include "mls_common.h"
#include "mls_crypto.h"
#include "mls_credential.h"

#ifdef __cplusplus
#include "mls/core_types.h"
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
    struct mls_extension *extensions;
    size_t extensions_size;
};

struct mls_key_package {
    mls_protocol_version version;
    mls_cipher_suite cipher_suite;
    struct mls_HPKE_public_key init_key;
    struct mls_credential credential;
    struct mls_extension_list extensions;
    uint8_t *signature;
    uint32_t signature_size;
};

struct mls_key_package mls_create_key_package(mls_cipher_suite suite,
                                              struct mls_HPKE_public_key HPKE_public_key,
                                              struct mls_credential credential,
                                              struct mls_signature_private_key signature_private_key);
#ifdef __cplusplus
struct mls_extension_list mls_from_extension_list(mls::ExtensionList extension_list);
}
#endif