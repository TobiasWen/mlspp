#include "mls_session.h"
#include "mls_primitives.h"
#include "mls_crypto.h"
#include "mls/session.h"
bool mls_temp_init_info(struct mls_init_info *target,
                        mls_cipher_suite suite,
                        struct mls_signature_private_key *identity_priv,
                        struct mls_credential *credential,
                        size_t size) {
    mls::bytes bytes = mls::random_bytes(size);
    mls_from_bytes(&target->init_secret, &bytes);
    mls_HPKE_private_key init_key{};
    init_key.data.data = (uint8_t *)malloc(size * sizeof(*init_key.data.data));
    init_key.data.size = size;
    mls_derive_HPKE_private_key(&init_key, suite, &target->init_secret);
    mls_create_key_package(&target->key_package, suite, &init_key.public_key, credential, identity_priv);
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
        *current_index++;
        return true;
    } else {
        return false;
    }
}

bool mls_to_init_info(mls::Session::InitInfo *target, struct mls_init_info *info) {
    if(target != nullptr && info != nullptr) {
        mls_to_bytes(&target->init_secret, &info->init_secret);
        mls_to_key_package(&target->key_package, &info->key_package);
        mls_convert_to_signature_private_key(&target->sig_priv, &info->sig_priv);
        return true;
    } else {
        return false;
    }
}

bool mls_session_start(struct mls_session_welcome_tuple *target,
                       struct mls_bytes *group_id,
                       struct mls_init_info *my_info,
                       size_t my_init_info_size,
                       struct mls_key_package *key_packages,
                       size_t key_packages_size,
                       struct mls_bytes *random_bytes) {
    if(target != nullptr &&
       group_id != nullptr &&
       my_info != nullptr &&
       key_packages != nullptr &&
       random_bytes != nullptr) {
        mls::bytes mls_group_id(group_id->size);
        mls_to_bytes(&mls_group_id, group_id);
        mls::bytes init_secret(my_info->init_secret.size);
        mls_to_bytes(&init_secret ,&my_info->init_secret);
        auto info = *new std::vector<mls::Session::InitInfo>(my_init_info_size);
        for(int i = 0; i < my_init_info_size; i++) {
            mls_to_init_info(&info[i], my_info + i * sizeof(*my_info));
        }
        auto kpckgs = *new std::vector<mls::KeyPackage>(key_packages_size);
        for(int i = 0; i < key_packages_size; i++) {
            mls_to_key_package(&kpckgs[i], key_packages + i * sizeof(*key_packages));
        }
        mls::bytes rnd_bytes(random_bytes->size);
        mls_to_bytes(&rnd_bytes, random_bytes);
        auto [session, welcome] =
        mls::Session::start(mls_group_id, info, kpckgs, rnd_bytes);
        void *session_data = reinterpret_cast<void*>(&session);
        void *welcome_data = reinterpret_cast<void*>(&welcome);
        target->session_size = sizeof(session);
        target->welcome_size = sizeof(welcome);
        memcpy(target->session, session_data, target->session_size);
        memcpy(target->welcome, welcome_data, target->welcome_size);
        return true;
    } else {
        return false;
    }
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