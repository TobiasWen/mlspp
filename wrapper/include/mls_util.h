#pragma once

#include "mls_core_types.h"
#include "stdio.h"
#include "stdint.h"

#ifdef __cplusplus
#include "mls/common.h"
extern "C" {
#endif


void printUint8Array(uint8_t *array, size_t array_size, char prefix[]);
bool points_to_heap(void* init_brk, void* pointer);
bool is_heap_var(void* pointer);
#ifdef __cplusplus
struct mls_bytes from_mls_bytes(mls::bytes *bytes);
}
#endif