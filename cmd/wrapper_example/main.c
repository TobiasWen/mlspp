#include "mls_common.h"
#include "mls_crypto.h"
#include "mls_credential.h"
#include "string.h"

struct user {
    
};

int main(int argc, const char* argv[])
{
    mls_cipher_suite suite = X25519_AES128GCM_SHA256_Ed25519;
    struct mls_signature_private_key priv_key = mls_generate_mls_signature_private_key(suite);
    struct mls_signature_public_key pub_key = mls_get_signature_public_key_from_private_key(priv_key);
    char name[] = "Alice";
    uint32_t length = strlen(name);
    struct mls_credential credential = mls_create_basic_credential((uint8_t*) &name[0], length, pub_key);
    struct mls_HPKE_private_key init_key = mls_derive_HPKE_private_key(suite, (uint8_t*) &name[0], length);
    helloC("Test\n");
};