#include "mls_session.h"
#include "mls_primitives.h"
#include "mls/session.h"
bool mls_temp_init_info(struct mls_init_info *target,
                        mls_cipher_suite suite,
                        struct mls_signature_private_key *identity_priv,
                        struct mls_credential *credential,
                        size_t size) {
    mls::bytes bytes = mls::random_bytes(size);
    mls_from_bytes(&target->init_secret, &bytes);
    mls_derive_HPKE_private_key(&target->key_package.init_key, suite, &target->init_secret);
    mls_create_key_package(&target->key_package, suite, &target->key_package.init_key, credential, identity_priv);
    target->sig_priv = *identity_priv;
}

bool mls_fresh_key_package(struct mls_key_package *target,
                           mls_cipher_suite suite,
                           struct mls_signature_private_key *identity_priv,
                           struct mls_credential *credential,
                           struct mls_init_info *infos,
                           int *current_index,
                           size_t size) {
    if(target != nullptr && identity_priv != nullptr && credential != nullptr && infos != nullptr) {
        mls_init_info *info = infos + *current_index * sizeof(*infos);
        mls_temp_init_info(info, suite, identity_priv, credential, size);
        *target = info->key_package;
        return true;
    } else {
        return false;
    }
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

bool mls_copy_init_info(struct mls_init_info *target, struct mls_init_info *src) {
    if(target != nullptr && src != nullptr) {
        mls_copy_bytes(&target->init_secret, &src->init_secret);
        mls_copy_key_package(&target->key_package, &src->key_package);
        mls_copy_bytes(&target->sig_priv.data, &src->sig_priv.data);
        mls_copy_bytes(&target->sig_priv.public_key.data, &src->sig_priv.public_key.data);
        target->sig_priv.signature_scheme = src->sig_priv.signature_scheme;
        target->sig_priv.cipher_suite = src->sig_priv.cipher_suite;
        target->sig_priv.public_key.signature_scheme = src->sig_priv.public_key.signature_scheme;
        return true;
    } else {
        return false;
    }
}