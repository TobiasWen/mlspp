#include "mls_common.h"
#include "mls_crypto.h"
#include "mls_credential.h"
#include "mls_primitives.h"
#include "mls_session.h"
#include "string.h"
#include "mls_util.h"

const mls_cipher_suite suite = X25519_AES128GCM_SHA256_Ed25519;
const size_t key_size = 32;

struct mls_user {
    struct mls_signature_private_key identity_priv;
    struct mls_init_info infos[100];
    int current_index;
    struct mls_credential credential;
};

struct mls_user* user_create(char name[], size_t name_size) {
    struct mls_user *user = malloc(sizeof(*user));
    mls_signature_private_key_instantiate(&user->identity_priv, suite, key_size);
    struct mls_bytes identity = {.data=(uint8_t*)&name[0], .size=name_size};
    mls_credential_instantiate(&user->credential, &identity, &user->identity_priv.public_key, key_size);
    return user;
}

bool user_destroy(struct mls_user *user) {
    if(user != NULL) {
        free(user->identity_priv.data.data);
        free(user->identity_priv.public_key.data.data);
        free(user);
        return true;
    } else {
        return false;
    }
}

int main(int argc, const char* argv[])
{
    ////////// DRAMATIS PERSONAE ///////////
    struct mls_user *alice = user_create("alice", 5);
    struct mls_user *bob = user_create("bob", 3);
    struct mls_user *charlie = user_create("charlie", 7);

    ////////// Cleanup ///////////
    user_destroy(alice);
    user_destroy(bob);
    user_destroy(charlie);
    helloC("Test\n");
};
