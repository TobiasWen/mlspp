#pragma once
#include "mls_core_types.h"
#ifdef __cplusplus

#include <map>
typedef std::map<uint64_t, char*> std_map_state;
typedef std::map<mls_bytes, mls_bytes> std_map_bytes;

extern "C" {
#endif
void* std_map_state_create();
void* std_map_bytes_create();

#ifdef __cplusplus

}
#endif