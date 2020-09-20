#pragma once

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
    struct mls_bytes data;
    size_t reserved_size;
};

struct mls_extension_list {
    struct mls_extension *extensions;
    size_t extensions_size;
    size_t reserved_size;
};

struct mls_key_package {
    mls_protocol_version version;
    mls_cipher_suite cipher_suite;
    struct mls_HPKE_public_key init_key;
    struct mls_credential credential;
    struct mls_extension_list extensions;
    struct mls_bytes signature;
};

bool mls_create_key_package(struct mls_key_package *target,
                            mls_cipher_suite suite,
                            struct mls_HPKE_public_key *HPKE_public_key,
                            struct mls_credential *credential,
                            struct mls_signature_private_key *signature_private_key);

#ifdef __cplusplus
bool mls_from_extension_list(struct mls_extension_list *target, mls::ExtensionList *src);
bool mls_from_extension(struct mls_extension *target, mls::Extension *src);
bool mls_to_extension_list(mls::ExtensionList *target, struct mls_extension_list *src);
bool mls_to_key_package(mls::KeyPackage *target, struct mls_key_package *src);
bool mls_copy_key_package(struct mls_key_package *target, struct mls_key_package *src);
bool mls_copy_extension_list(struct mls_extension_list *target, struct mls_extension_list *src);
}
#endif