#pragma once
#include "stdint.h"

#ifdef __cplusplus
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

void helloC(char name[]);
#ifdef __cplusplus
}
#endif