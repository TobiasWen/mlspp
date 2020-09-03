#pragma once
#include "mls_common.h"
#include "mls_crypto.h"
#include "mls_core_types.h"
#ifdef __cplusplus
extern "C" {
#endif
struct mls_init_info {
    uint8_t *init_secret;
    uint32_t init_secret_size;
    mls_signature_private_key sig_priv;
    mls_key_package key_package;
};

#ifdef __cplusplus

}
#endif