#include "mls_common.h"
#include "mls_crypto.h"
#include "mls_credential.h"
#include "mls_primitives.h"
#include "mls_session.h"
#include "string.h"
#include "mls_util.h"

const mls_cipher_suite suite = X25519_AES128GCM_SHA256_Ed25519;

struct mls_user {
    struct mls_signature_private_key identity_priv;
    struct mls_init_info infos[100];
    int current_index;
    struct mls_credential credential;
};

struct mls_user create_user(char name[], size_t name_size) {
    struct mls_user user = {0};
    user.identity_priv = mls_generate_mls_signature_private_key(suite);
    struct mls_signature_public_key identity_pub = mls_get_signature_public_key_from_private_key(user.identity_priv);
    user.credential = mls_create_basic_credential((uint8_t*) &name[0], name_size, identity_pub);
    return user;
}

int main(int argc, const char* argv[])
{
    ////////// DRAMATIS PERSONAE ///////////

    struct mls_user alice = create_user("alice", 5);
    struct mls_user bob = create_user("bob", 3);
    struct mls_user charlie = create_user("charlie", 7);

    ////////// ACT I: CREATION ///////////

    // Bob posts a KeyPackage
    struct mls_key_package kpB = mls_fresh_key_package(suite, bob.identity_priv, bob.credential, bob.infos, bob.current_index);
    bob.current_index++;

    // Alice starts a session with Bob
    struct mls_init_info info_a = mls_temp_init_info(suite, alice.identity_priv, alice.credential);
    struct mls_bytes group_id = {.data = {0, 1, 2, 3}, .size = 4};
    // TODO: die random_bytes wurden von der mls lib nicht auf dem heap allokiert. Potentiell andere Stellen finden
    // wo das nicht der fall ist.
    struct mls_bytes rand_bytes = mls_generate_random_bytes(32);
    printUint8Array(rand_bytes.data, rand_bytes.size, "Test!");
    struct mls_session_welcome_tuple session_welcome = mls_session_start(group_id, &info_a, 1, &kpB, 1, rand_bytes);
    /*struct mls_signature_private_key priv_key = mls_generate_mls_signature_private_key(suite);
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
    struct mls_key_package kp = mls_create_key_package(suite, hpke_pub_key, credential, priv_key);*/
    helloC("Test\n");
};
