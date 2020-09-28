#include <cstring>
#include "mls_session.h"
#include "mls_primitives.h"
#include "mls_crypto.h"
#include "mls/session.h"
#include <iostream>

bool mls_temp_init_info_instantiate(struct mls_init_info *target, mls_cipher_suite suite,
                                    struct mls_signature_private_key *identity_priv, struct mls_credential *credential,
                                    size_t size) {
    if (target != nullptr && identity_priv != nullptr && credential != nullptr) {
        mls_signature_private_key_instantiate(&target->sig_priv, suite, size);
        mls_key_package_allocate(&target->key_package, &credential->cred.identity, size);
        mls_bytes_allocate(&target->init_secret, size);
        mls_temp_init_info(target, suite, identity_priv, credential, size);
        return true;
    } else {
        return true;
    }
}

bool mls_temp_init_info_destroy(struct mls_init_info *target) {
    if (target != nullptr) {
        mls_signature_private_key_destroy(&target->sig_priv);
        mls_key_package_destroy(&target->key_package);
        mls_bytes_destroy(&target->init_secret);
        free(target);
        return true;
    } else {
        return true;
    }
}

bool mls_temp_init_info(struct mls_init_info *target,
                        mls_cipher_suite suite,
                        struct mls_signature_private_key *identity_priv,
                        struct mls_credential *credential,
                        size_t size) {
    if (target != nullptr && identity_priv != nullptr && credential != nullptr) {
        mls::bytes bytes = mls::random_bytes(size);
        mls_from_bytes(&target->init_secret, &bytes);
        mls_HPKE_private_key init_key{};
        mls_hpke_private_key_allocate(&init_key, size);
        mls_derive_HPKE_private_key(&init_key, suite, &target->init_secret);
        mls_create_key_package(&target->key_package, suite, &init_key.public_key, credential, identity_priv);
        target->sig_priv = *identity_priv;
        return true;
    } else {
        return false;
    }
}

bool mls_fresh_key_package_destroy(struct mls_key_package *target) {
    if (target != nullptr) {
        mls_bytes_destroy(&target->signature);
        mls_credential_destroy(&target->credential);
        mls_extension_list_destroy(&target->extensions);
        mls_hpke_public_key_destroy(&target->init_key);
        free(target);
        return true;
    } else {
        return true;
    }
}

bool mls_fresh_key_package(struct mls_key_package *target,
                           mls_cipher_suite suite,
                           struct mls_signature_private_key *identity_priv,
                           struct mls_credential *credential,
                           struct mls_init_info *infos,
                           int *current_index,
                           size_t size) {
    if (target != nullptr && identity_priv != nullptr && credential != nullptr && infos != nullptr && current_index !=
                                                                                                      nullptr) {
        mls_init_info *info = infos + *current_index * sizeof(*infos);
        mls_temp_init_info_instantiate(info, suite, identity_priv, credential, size);
        *target = info->key_package;
        (*current_index)++;
        return true;
    } else {
        return false;
    }
}

bool mls_to_init_info(mls::Session::InitInfo *target, struct mls_init_info *info) {
    if (target != nullptr && info != nullptr) {
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
    if (target != nullptr &&
        group_id != nullptr &&
        my_info != nullptr &&
        key_packages != nullptr &&
        random_bytes != nullptr) {
        mls::bytes mls_group_id(group_id->size);
        mls_to_bytes(&mls_group_id, group_id);
        mls::bytes init_secret(my_info->init_secret.size);
        mls_to_bytes(&init_secret, &my_info->init_secret);
        std::vector<mls::Session::InitInfo> info(my_init_info_size);
        for (int i = 0; i < my_init_info_size; i++) {
            info.at(i).init_secret = mls::bytes((my_info + i * sizeof(*my_info))->init_secret.size);
            info.at(i).sig_priv._data = mls::bytes((my_info + i * sizeof(*my_info))->sig_priv.data.size);
            info.at(i).sig_priv._pub_data = mls::bytes((my_info + i * sizeof(*my_info))->sig_priv.public_key.data.size);
            info.at(i).key_package.extensions.extensions = std::vector<mls::Extension>((my_info + i * sizeof(*my_info))->key_package.extensions.extensions_size);
            for(int j = 0; j < (my_info + i * sizeof(*my_info))->key_package.extensions.extensions_size; j++) {
                info.at(i).key_package.extensions.extensions.at(j).data = mls::bytes((my_info + i * sizeof(*my_info))->key_package.extensions.extensions[j].data.size);
            }
            info.at(i).key_package.init_key.data = mls::bytes((my_info + i * sizeof(*my_info))->key_package.init_key.data.size);
            info.at(i).key_package.signature = mls::bytes((my_info + i * sizeof(*my_info))->key_package.signature.size);
            mls_to_init_info(&info.at(i), my_info + i * sizeof(*my_info));
        }
        std::vector<mls::KeyPackage> kpckgs(key_packages_size);
        for (int i = 0; i < key_packages_size; i++) {
            kpckgs.at(i).extensions.extensions = std::vector<mls::Extension>((key_packages + i * sizeof(*key_packages))->extensions.extensions_size);
            for(int j = 0; j < (key_packages + i * sizeof(*key_packages))->extensions.extensions_size; j++) {
                kpckgs.at(i).extensions.extensions.at(j).data = mls::bytes((key_packages + i * sizeof(*key_packages))->extensions.extensions[j].data.size);
            }
            kpckgs.at(i).init_key.data = mls::bytes((key_packages + i * sizeof(*key_packages))->init_key.data.size);
            kpckgs.at(i).signature = mls::bytes((key_packages + i * sizeof(*key_packages))->signature.size);
            mls_to_key_package(&kpckgs.at(i), key_packages + i * sizeof(*key_packages));
        }
        mls::bytes rnd_bytes(random_bytes->size);
        mls_to_bytes(&rnd_bytes, random_bytes);

        auto[session, welcome] =
        mls::Session::start(mls_group_id, info, kpckgs, rnd_bytes);
        mls::Session* session_heap = new mls::Session(session);
        void *session_data = reinterpret_cast<void *>(session_heap);
        mls::bytes welcome_bytes = tls::marshal(welcome);
        target->session.size = sizeof(*session_heap);
        target->session.data = malloc(target->session.size);
        memcpy(target->session.data, session_data, target->session.size);
        target->welcome.bytes.size = welcome_bytes.size();
        mls_from_bytes(&target->welcome.bytes, &welcome_bytes);
        return true;
    } else {
        return false;
    }
}

bool mls_session_join(struct mls_session *target, struct mls_init_info *infos, size_t infos_size, struct mls_session_welcome_tuple *session_welcome) {
    std::vector<mls::Session::InitInfo> info(infos_size);
    for (int i = 0; i < infos_size; i++) {
        info.at(i).init_secret = mls::bytes((infos + i * sizeof(*infos))->init_secret.size);
        info.at(i).sig_priv._data = mls::bytes((infos + i * sizeof(*infos))->sig_priv.data.size);
        info.at(i).sig_priv._pub_data = mls::bytes((infos + i * sizeof(*infos))->sig_priv.public_key.data.size);
        info.at(i).key_package.extensions.extensions = std::vector<mls::Extension>((infos + i * sizeof(*infos))->key_package.extensions.extensions_size);
        for(int j = 0; j < (infos + i * sizeof(*infos))->key_package.extensions.extensions_size; j++) {
            info.at(i).key_package.extensions.extensions.at(j).data = mls::bytes((infos + i * sizeof(*infos))->key_package.extensions.extensions[j].data.size);
        }
        info.at(i).key_package.init_key.data = mls::bytes((infos + i * sizeof(*infos))->key_package.init_key.data.size);
        info.at(i).key_package.signature = mls::bytes((infos + i * sizeof(*infos))->key_package.signature.size);
        mls_to_init_info(&info.at(i), infos + i * sizeof(*infos));
    }
    mls::Welcome mls_welcome;
    mls::bytes welcome_bytes(session_welcome->welcome.bytes.size);
    mls_to_bytes(&welcome_bytes, &session_welcome->welcome.bytes);
    tls::unmarshal(welcome_bytes, mls_welcome);
    auto session = mls::Session::join(info, mls_welcome);
    mls::Session* session_heap = new mls::Session(session);
    void *session_data = reinterpret_cast<void *>(session_heap);
    target->size = sizeof(session);
    target->data = session_data;
    return true;
}

bool mls_copy_init_info(struct mls_init_info *target, struct mls_init_info *src) {
    if (target != nullptr && src != nullptr) {
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