#include "mls_session.h"
#include "mls_primitives.h"

struct mls_init_info mls_temp_init_info(mls_cipher_suite suite, mls_signature_private_key identity_priv, mls_credential credential) {
    struct mls_init_info init_info{};
    size_t size = 32;
    mls_random_bytes bytes = mls_generate_random_bytes(size);
    init_info.init_secret = bytes.bytes;
    init_info.init_secret_size = bytes.size;
    struct mls_HPKE_private_key init_key = mls_derive_HPKE_private_key(suite, init_info.init_secret, init_info.init_secret_size);
    struct mls_HPKE_public_key hpke_pub_key{};
    hpke_pub_key.data = init_key.pub_data;
    hpke_pub_key.data_size = init_key.pub_data_size;
    struct mls_key_package kp = mls_create_key_package(suite, hpke_pub_key, credential, identity_priv);
    init_info.key_package = kp;
    init_info.sig_priv = identity_priv;
    return init_info;
}

struct mls_key_package mls_fresh_key_package(mls_cipher_suite suite, mls_signature_private_key identity_priv, mls_credential credential, mls_init_info *infos, int current_index) {
    struct mls_key_package kp{};
    struct mls_init_info info = mls_temp_init_info(suite, identity_priv, credential);
    infos[current_index] = info;
    return info.key_package;
}