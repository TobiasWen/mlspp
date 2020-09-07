#include "mls_common.h"
#include "mls_crypto.h"
#include "mls_credential.h"
#include "mls_primitives.h"
#include "string.h"
#include "stdio.h"

struct user {
    
};

int main(int argc, const char* argv[])
{
    mls_cipher_suite suite = X25519_AES128GCM_SHA256_Ed25519;
    struct mls_signature_private_key priv_key = mls_generate_mls_signature_private_key(suite);
    struct mls_signature_public_key pub_key = mls_get_signature_public_key_from_private_key(priv_key);
    char name[] = "Alice";
    uint32_t length = strlen(name);
    struct mls_random_bytes init_secret = mls_generate_random_bytes(32);
    // TODO: Maybe create struct mls_bytes and implement it.
    struct mls_credential credential = mls_create_basic_credential((uint8_t*) &name[0], length, pub_key);
    struct mls_HPKE_private_key init_key = mls_derive_HPKE_private_key(suite, (uint8_t*) &name[0], length);
    struct mls_HPKE_public_key hpke_pub_key = {0};
    hpke_pub_key.data = init_key.pub_data;
    hpke_pub_key.data_size = init_key.pub_data_size;
    struct mls_key_package kp = mls_create_key_package(suite, hpke_pub_key, credential, priv_key);
    for(int i = 0; i < kp.extensions.extensions_size; i++) {
        printf("Extension from %d is %u \n", i, (kp.extensions.extensions + i)->type);
    }
    helloC("Test\n");
};