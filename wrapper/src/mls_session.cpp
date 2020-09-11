#include "mls_session.h"
#include "mls_primitives.h"
#include "mls/session.h"

struct mls_init_info
mls_temp_init_info(mls_cipher_suite suite, mls_signature_private_key identity_priv, mls_credential credential) {
    struct mls_init_info init_info{};
    size_t size = 32;
    mls_bytes bytes = mls_generate_random_bytes(size);
    init_info.init_secret = bytes.data;
    init_info.init_secret_size = bytes.size;
    struct mls_HPKE_private_key init_key = mls_derive_HPKE_private_key(suite, init_info.init_secret,
                                                                       init_info.init_secret_size);
    struct mls_HPKE_public_key hpke_pub_key{};
    hpke_pub_key.data = init_key.pub_data;
    hpke_pub_key.data_size = init_key.pub_data_size;
    struct mls_key_package kp = mls_create_key_package(suite, hpke_pub_key, credential, identity_priv);
    init_info.key_package = kp;
    init_info.sig_priv = identity_priv;
    return init_info;
}

struct mls_key_package
mls_fresh_key_package(mls_cipher_suite suite, mls_signature_private_key identity_priv, mls_credential credential,
                      mls_init_info *infos, int current_index) {
    struct mls_init_info info = mls_temp_init_info(suite, identity_priv, credential);
    *(infos + current_index * sizeof(*infos)) = info;
    return info.key_package;
}

mls::Session::InitInfo mls_to_init_info(struct mls_init_info info) {
    mls::bytes init_secret_in(info.init_secret, info.init_secret + info.init_secret_size);
    mls::SignaturePrivateKey sig_priv_in = mls_convert_to_signature_private_key(info.sig_priv);
    mls::KeyPackage key_package = mls_to_key_package(info.key_package);
    auto *mls_info = new mls::Session::InitInfo(init_secret_in, sig_priv_in, key_package);
    return *mls_info;
}

struct mls_session_welcome_tuple mls_session_start(struct mls_bytes group_id,
                                                   mls_init_info *my_info, size_t my_init_info_size,
                                                   mls_key_package *key_packages, size_t key_packages_size,
                                                   struct mls_bytes random_bytes) {
    struct mls_session_welcome_tuple tuple = {};
    auto info = *new std::vector<mls::Session::InitInfo>();
    for(int i = 0; i < my_init_info_size; i++) {
        for(int x = 0; x < (my_info + i * sizeof(*my_info))->init_secret_size; x++) {
            printf("My_InitInfo %d%hhu\n", i, *((my_info + i * sizeof(*my_info))->init_secret + x * sizeof(uint8_t)));
            fflush(stdout);
        }
        info.push_back(mls_to_init_info(*(my_info + i * sizeof(*my_info))));
    }
    auto kpckgs = *new std::vector<mls::KeyPackage>();
    for(int i = 0; i < key_packages_size; i++) {
        //TODO: Fix Maybe this doesnt work like that with the indices!
        kpckgs.push_back(mls_to_key_package(*(key_packages + i * sizeof(*key_packages))));
    }
    mls::bytes mls_group_id(group_id.data, group_id.data + group_id.size);
    mls::bytes rnd_bytes(random_bytes.data, random_bytes.data + random_bytes.size);
    auto [session, welcome] =
    mls::Session::start(mls_group_id, info, kpckgs, rnd_bytes);
    tuple.session = reinterpret_cast<void*>(&session);
    tuple.welcome = reinterpret_cast<void*>(&welcome);
    return tuple;
}