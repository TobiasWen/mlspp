#pragma once
#include "mls_common.h"
#include "mls_crypto.h"
#include "mls_core_types.h"
#ifdef __cplusplus
#include "mls/primitives.h"
extern "C" {
#endif
struct mls_random_bytes {
    uint8_t *bytes;
    size_t size;
};

struct mls_random_bytes mls_generate_random_bytes(size_t size);
#ifdef __cplusplus

}
#endif