#include <cstring>
#include "mls_core_types.h"
#include "mls/core_types.h"

bool mls_key_package_allocate(struct mls_key_package *target, mls_bytes *identity, size_t key_size) {
    if(target != nullptr) {
        mls_credential_allocate(&target->credential, identity, key_size);
        mls_bytes_allocate(&target->signature, key_size * 2);
        mls_hpke_public_key_allocate(&target->init_key, key_size);
        mls_extension_list_allocate(&target->extensions);
        return true;
    } else {
        return false;
    }
}

bool mls_key_package_destroy(struct mls_key_package *target) {
    if (target != nullptr) {
        mls_credential_destroy(&target->credential);
        mls_bytes_destroy(&target->signature);
        mls_hpke_public_key_destroy(&target->init_key);
        mls_extension_list_destroy(&target->extensions);
        free(target);
        return true;
    } else {
        return false;
    }
}

bool mls_create_key_package(mls_key_package *target,
                            mls_cipher_suite suite,
                            struct mls_HPKE_public_key *HPKE_public_key,
                            struct mls_credential *credential,
                            struct mls_signature_private_key *signature_private_key) {
    if(target != nullptr && HPKE_public_key != nullptr && credential != nullptr && signature_private_key != nullptr) {
        mls::HPKEPublicKey mls_hpke_pub_key;
        mls_hpke_pub_key.data = mls::bytes(HPKE_public_key->data.size);
        mls_convert_to_HPKE_public_key(&mls_hpke_pub_key, HPKE_public_key);
        mls::Credential mls_cred;
        mls_to_credential(&mls_cred, credential);
        mls::SignaturePrivateKey identity_priv;
        identity_priv._data = mls::bytes(signature_private_key->data.size);
        identity_priv._pub_data = mls::bytes(signature_private_key->public_key.data.size);
        mls_convert_to_signature_private_key(&identity_priv, signature_private_key);
        mls::KeyPackage package = mls::KeyPackage{ (mls::CipherSuite) suite, mls_hpke_pub_key, mls_cred, identity_priv };
        if(target->signature.size != package.signature.size()) return false;
        mls_from_credential(&(target->credential), &package.credential);
        mls_convert_from_HPKE_public_key(&(target->init_key), &package.init_key);
        target->cipher_suite = (mls_cipher_suite) package.cipher_suite;
        mls_from_extension_list(&(target->extensions), &package.extensions);
        // TODO: note that the signature size and memory has to be allocated beforehand
        mls_from_bytes(&target->signature, &package.signature);
        target->version = (mls_protocol_version) package.version;
        return true;
    } else {
        return false;
    }
}

bool mls_extension_list_allocate(struct mls_extension_list *target) {
    if(target != nullptr) {
        target->reserved_size = 16;
        target->extensions = (struct mls_extension*) malloc(target->reserved_size * sizeof(*target->extensions));
        for(int i = 0; i < target->reserved_size; i++) {
            target->extensions[i].reserved_size = 100;
            target->extensions[i].data.data = (uint8_t*) malloc(sizeof(target->extensions[i].data));
        }
        return true;
    } else {
        return false;
    }
}

bool mls_extension_list_destroy(struct mls_extension_list *target) {
    if(target != nullptr) {
        for(int i = 0; i < target->reserved_size; i++) {
            mls_bytes_destroy(&target->extensions[i].data);
            //free(&target->extensions[i]); <--- Should not be needed
        }
        free(target->extensions);
        free(target);
        return true;
    } else {
        return false;
    }
}

bool mls_from_extension_list(struct mls_extension_list *target, mls::ExtensionList *src) {
    if(target != nullptr && src != nullptr) {
        if(src->extensions.size() > target->reserved_size) return false;
        target->extensions_size = src->extensions.size();
        for(int i = 0; i < src->extensions.size(); i++) {
            mls_from_extension(&target->extensions[i], &src->extensions[i]);
        }
        return true;
    } else {
        return false;
    }
}

bool mls_from_extension(struct mls_extension *target, mls::Extension *src) {
    if(src->data.size() > target->reserved_size) return false;
    memcpy(target->data.data, (uint8_t*) &src->data[0], src->data.size());
    target->data.size = src->data.size();
    target->type = (mls_extension_type) src->type;
    return true;
}

bool mls_to_extension_list(mls::ExtensionList *target, struct mls_extension_list *src) {
    if(target != nullptr && src != nullptr) {
        for(int i = 0; i < src->extensions_size; i++) {
            target->extensions[i].type = (mls::ExtensionType)src->extensions[i].type;
            mls_to_bytes(&target->extensions.at(i).data, &src->extensions[i].data);
        }
        return true;
    } else {
        return false;
    }
}

bool mls_to_key_package(mls::KeyPackage *target, struct mls_key_package *src) {
    if(target != nullptr && src != nullptr) {
        if(src->signature.size != target->signature.size()) return false;
        target->version = (mls::ProtocolVersion) src->version;
        target->cipher_suite = (mls::CipherSuite) src->cipher_suite;
        mls_convert_to_HPKE_public_key(&target->init_key, &src->init_key);
        mls_to_credential(&target->credential, &src->credential);
        mls_to_extension_list(&target->extensions, &src->extensions);
        mls_to_bytes(&target->signature, &src->signature);
        return true;
    } else {
        return false;
    }
}

bool mls_copy_key_package(struct mls_key_package *target, struct mls_key_package *src) {
    if(target != nullptr && src != nullptr) {
        target->cipher_suite = src->cipher_suite;
        target->version = src->version;
        mls_copy_bytes(&target->signature, &src->signature);
        mls_copy_bytes(&target->init_key.data, &src->init_key.data);
        mls_copy_extension_list(&target->extensions, &src->extensions);
        mls_copy_credential(&target->credential, &src->credential);
        return true;
    } else {
        return false;
    }
}

bool mls_copy_extension_list(struct mls_extension_list *target, struct mls_extension_list *src) {
    if(target != nullptr && src != nullptr) {
        target->extensions_size = src->extensions_size;
        target->reserved_size = src->reserved_size;
        memcpy(target->extensions, src->extensions, src->reserved_size);
        return true;
    } else {
        return false;
    }
}