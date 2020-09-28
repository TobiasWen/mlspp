#include "mls_common.h"
#include "mls_crypto.h"
#include "mls_credential.h"
#include "mls_primitives.h"
#include "mls_session.h"
#include "string.h"


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

    ////////// ACT I: CREATION ///////////
    // Bob posts a KeyPackage
    struct mls_key_package kp_b = {0};
    mls_fresh_key_package(&kp_b, suite, &bob->identity_priv, &bob->credential, bob->infos, &bob->current_index, key_size);

    // Alice starts a session with Bob
    struct mls_init_info info_a = {0};
    struct mls_key_package kpckgs[] = { kp_b };
    mls_temp_init_info_instantiate(&info_a, suite, &alice->identity_priv, &alice->credential, key_size);
    struct mls_init_info infos[] = { info_a };
    struct mls_bytes groupd_id;
    uint8_t group_id_data[4];
    group_id_data[0] = 0;
    group_id_data[1] = 1;
    group_id_data[2] = 2;
    group_id_data[3] = 3;
    groupd_id.size = 4;
    groupd_id.data = &group_id_data[0];
    struct mls_session_welcome_tuple session_welcome = {0};
    session_welcome.session.data = malloc(1000);
    session_welcome.session.size_reserved = 1000;
    session_welcome.welcome.size_reserved = 1000;
    uint8_t welcome_bytes[session_welcome.welcome.size_reserved];
    session_welcome.welcome.bytes.data = &welcome_bytes[0];
    struct mls_bytes rnd_bytes = {};
    uint8_t rnd_bytes_data[key_size];
    rnd_bytes.size = key_size;
    rnd_bytes.data = &rnd_bytes_data[0];
    mls_generate_random_bytes(&rnd_bytes, key_size);
    mls_session_start(&session_welcome, &groupd_id, &infos[0], 1, &kpckgs[0], 1, &rnd_bytes);

    // Bob looks up his CIK based on the welcome, and initializes
    // his session
    struct mls_session sessionB;
    sessionB.data = malloc(1000);
    sessionB.size_reserved = 1000;
    mls_session_join(&sessionB, &bob->infos[0], bob->current_index, &session_welcome);
    // Alice and Bob should now be on the same page

    helloC("Test\n");
};
