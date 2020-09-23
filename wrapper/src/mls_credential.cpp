#include "mls_credential.h"
#include "mls/crypto.h"


bool mls_credential_allocate(struct mls_credential *target, struct mls_bytes *identity, size_t key_size) {
    if(target != nullptr && identity != nullptr) {
        mls_bytes_allocate(&target->cred.identity, identity->size);
        mls_bytes_allocate(&target->cred.public_key.data, key_size);
        return true;
    } else {
        return false;
    }
}

bool mls_credential_instantiate(struct mls_credential *target, struct mls_bytes *identity, struct mls_signature_public_key *public_key, size_t key_size) {
    if(target != nullptr && identity != nullptr && public_key != nullptr) {
        mls_credential_allocate(target, identity, key_size);
        mls_create_basic_credential(target, identity, public_key);
        return true;
    } else {
        return false;
    }
}

bool mls_credential_destroy(struct mls_credential *target) {
    if(target != nullptr) {
        mls_bytes_destroy(&target->cred.public_key.data);
        mls_bytes_destroy(&target->cred.identity);
        free(target);
        return true;
    } else {
        return false;
    }
}

bool mls_create_basic_credential(struct mls_credential *target, mls_bytes *identity, struct mls_signature_public_key *public_key) {
    if(target != nullptr && identity != nullptr && public_key != nullptr) {
        mls::bytes mls_identity(identity->data, identity->data + identity->size);
        mls::SignaturePublicKey mls_pub_key;
        mls_pub_key._data = mls::bytes(public_key->data.size);
        mls_convert_to_signature_public_key(&mls_pub_key, public_key);
        mls::Credential basic_cred = mls::Credential::basic(mls_identity, mls_pub_key);
        mls_from_credential(target, &basic_cred);
        return true;
    } else {
        return false;
    }
}

bool mls_from_credential(struct mls_credential *target, mls::Credential *src) {
    if(target != nullptr && src != nullptr) {
        mls_from_basic_credential(&target->cred, &std::get<mls::BasicCredential>(src->_cred));
        return true;
    } else {
        return false;
    }
}

bool mls_from_basic_credential(struct mls_basic_credential *target, mls::BasicCredential *src) {
    if(target != nullptr && src != nullptr) {
        mls_from_bytes(&target->identity, &src->identity);
        mls_convert_from_signature_public_key(&target->public_key, &src->public_key);
        target->type = (mls_credential_type) src->type;
        return true;
    } else {
        return false;
    }
}

bool mls_to_credential(mls::Credential *target, struct mls_credential *src) {
    if(target != nullptr && src != nullptr) {
        mls::BasicCredential credential = std::get<mls::BasicCredential>(target->_cred);
        credential.public_key._data = mls::bytes(src->cred.public_key.data.size);
        credential.identity = mls::bytes(src->cred.identity.size);
        mls_to_basic_credential(&credential, &src->cred);
        target->_cred = credential;
        return true;
    } else {
        return false;
    }
}

bool mls_to_basic_credential(mls::BasicCredential *target, struct mls_basic_credential *src) {
    if(target != nullptr && src != nullptr) {
        mls_convert_to_signature_public_key(&target->public_key, &src->public_key);
        mls_to_bytes(&target->identity, &src->identity);
        target->type = (mls::CredentialType) src->type;
        return true;
    } else {
        return false;
    }
}

bool mls_copy_credential(mls_credential *target, struct mls_credential *src) {
    if(target != nullptr && src != nullptr) {
        target->cred.type = src->cred.type;
        mls_copy_bytes(&target->cred.identity, &src->cred.identity);
        mls_copy_bytes(&target->cred.public_key.data, &src->cred.public_key.data);
        target->cred.public_key.signature_scheme = src->cred.public_key.signature_scheme;
        return true;
    } else {
        return false;
    }
}