#include "mls_session.h"
#include "mls_primitives.h"
#include "mls/session.h"
bool mls_temp_init_info(struct mls_init_info *target,
                        mls_cipher_suite suite,
                        struct mls_signature_private_key *identity_priv,
                        struct mls_credential *credential,
                        size_t size,
                        size_t identity_size,
                        size_t extensions_reserved_size) {
    mls::bytes bytes = mls::random_bytes(size);

    // Reserve memory for temporal private init key
    mls_HPKE_private_key init_key = {nullptr};
    uint8_t init_key_data[size];
    uint8_t init_pub_key_data[size];
    init_key.data.data = &init_key_data[0];
    init_key.data.size = size;
    init_key.public_key.data.data = &init_pub_key_data[0];
    init_key.public_key.data.size = size;
    mls_derive_HPKE_private_key(&init_key, suite, &target->init_secret);

    // Reserve memory for temporal key package
    mls_key_package kp = {nullptr};
    uint8_t kp_init_key_data[size];
    uint8_t signature[size];
    uint8_t identity[identity_size];
    uint8_t kp_cred_public_key_data[size];
    mls_extension extension_list[extensions_reserved_size];
    kp.init_key.data.data = &kp_init_key_data[0];
    kp.init_key.data.size = size;
    kp.signature.data = &signature[0];
    kp.signature.size = size;
    kp.credential.cred.identity.data = &identity[0];
    kp.credential.cred.identity.size = identity_size;
    kp.credential.cred.public_key.data.data = &kp_cred_public_key_data[0];
    kp.credential.cred.public_key.data.size = size;
    kp.extensions.reserved_size = extensions_reserved_size;
    kp.extensions.extensions = &extension_list[0];
    mls_create_key_package(&kp, suite, &init_key.public_key, credential, identity_priv);

    // Copy values
    mls_from_bytes(&target->init_secret, &bytes);
    target->sig_priv = *identity_priv;
    mls_copy_key_package(&target->key_package, &kp);
}

bool mls_fresh_key_package(struct mls_key_package *target,
                           mls_cipher_suite suite,
                           struct mls_signature_private_key *identity_priv,
                           struct mls_credential *credential,
                           struct mls_init_info *infos,
                           int current_index,
                           size_t size,
                           size_t identity_size,
                           size_t extensions_reserved_size) {
    if(target != nullptr && identity_priv != nullptr && credential != nullptr && infos != nullptr) {
        struct mls_init_info info = {};
        mls::bytes bytes = mls::random_bytes(size);

        // Reserve memory for temporal private init key
        mls_HPKE_private_key init_key = {nullptr};
        uint8_t init_key_data[size];
        uint8_t init_pub_key_data[size];
        init_key.data.data = &init_key_data[0];
        init_key.data.size = size;
        init_key.public_key.data.data = &init_pub_key_data[0];
        init_key.public_key.data.size = size;
        mls_derive_HPKE_private_key(&init_key, suite, &info.init_secret);

        // Reserve memory for temporal key package
        mls_key_package kp = {nullptr};
        uint8_t kp_init_key_data[size];
        uint8_t signature[size];
        uint8_t identity[identity_size];
        uint8_t kp_cred_public_key_data[size];
        mls_extension extension_list[extensions_reserved_size];
        kp.init_key.data.data = &kp_init_key_data[0];
        kp.init_key.data.size = size;
        kp.signature.data = &signature[0];
        kp.signature.size = size;
        kp.credential.cred.identity.data = &identity[0];
        kp.credential.cred.identity.size = identity_size;
        kp.credential.cred.public_key.data.data = &kp_cred_public_key_data[0];
        kp.credential.cred.public_key.data.size = size;
        kp.extensions.reserved_size = extensions_reserved_size;
        kp.extensions.extensions = &extension_list[0];
        mls_create_key_package(&kp, suite, &init_key.public_key, credential, identity_priv);

        // Copy values
        mls_from_bytes(&info.init_secret, &bytes);
        info.sig_priv = *identity_priv;
        mls_copy_key_package(&info.key_package, &kp);

        mls_temp_init_info(&info, suite, identity_priv, credential, size, identity_size, extensions_reserved_size);

        mls_copy_init_info(infos + current_index * sizeof(*infos), &info);
        mls_copy_key_package(target, &info.key_package);
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