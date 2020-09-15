#pragma once
#include "mls_common.h"
#include "mls_crypto.h"
#include "mls_core_types.h"
#ifdef __cplusplus
#include "mls/primitives.h"
extern "C" {
#endif

bool mls_generate_random_bytes(struct mls_bytes *target, size_t size);
#ifdef __cplusplus

}
#endif