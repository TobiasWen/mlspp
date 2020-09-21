#pragma once

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#ifdef __cplusplus
#include "mls/common.h"
extern "C" {
#endif
typedef enum
{
    unknown = 0x0000,
    X25519_AES128GCM_SHA256_Ed25519 = 0x0001,
    P256_AES128GCM_SHA256_P256 = 0x0002,
    X25519_CHACHA20POLY1305_SHA256_Ed25519 = 0x0003,
    X448_AES256GCM_SHA512_Ed448 = 0x0004,
    P521_AES256GCM_SHA512_P521 = 0x0005,
    X448_CHACHA20POLY1305_SHA512_Ed448 = 0x0006,
} mls_cipher_suite;

typedef enum
{
    P256_SHA256 = 0x0403,
    P521_SHA512 = 0x0603,
    Ed25519 = 0x0807,
    Ed448 = 0x0808,
} mls_signature_scheme;

struct mls_bytes {
    uint8_t *data;
    size_t size;
};

bool mls_bytes_allocate(struct mls_bytes *bytes, size_t size);
bool mls_bytes_destroy(struct mls_bytes *bytes);
bool mls_create_bytes(struct mls_bytes *target, uint8_t *data, size_t size);
bool mls_copy_bytes(struct mls_bytes *target, struct mls_bytes *src);
void helloC(char name[]);
#ifdef __cplusplus
bool mls_from_bytes(struct mls_bytes *target, mls::bytes *origin);
bool mls_to_bytes(mls::bytes *target, struct mls_bytes *origin);
}
#endif