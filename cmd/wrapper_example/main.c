#include <stdlib.h>
#include "string.h"
#include "stdbool.h"

#include "mls_common.h"
#include "mls_crypto.h"
#include "mls_credential.h"

struct user {
    
};

int main(int argc, const char* argv[])
{
    mls_cipher_suite suite = X25519_AES128GCM_SHA256_Ed25519;
    struct mls_signature_private_key priv_key = mls_generate_mls_signature_private_key(suite);
    struct mls_signature_public_key pub_key = mls_get_signature_public_key_from_private_key(priv_key);

    struct mls_signature_public_key *pub_key_test = malloc(sizeof(struct mls_signature_public_key));
    bool success = mls_get_signature_public_key_from_private_key_test(priv_key, pub_key_test);
    free(pub_key_test);
};