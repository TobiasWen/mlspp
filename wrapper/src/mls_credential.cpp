#include "mls_credential.h"
#include "mls/crypto.h"

bool mls_create_basic_credential(struct mls_credential *target, mls_bytes *identity, struct mls_signature_public_key *public_key) {
    if(target != nullptr && identity != nullptr && public_key != nullptr) {
        mls::bytes mls_identity(identity->data, identity->data + identity->size);
        mls::SignaturePublicKey mls_pub_key;
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

mls::Credential mls_to_credential(struct mls_credential cred) {
    mls::Credential credential = mls::Credential{};
    mls::BasicCredential basic_credential = mls::BasicCredential();
    basic_credential.public_key = mls_convert_to_signature_public_key(cred.cred.public_key);
    mls::bytes mls_identity(cred.cred.identity, cred.cred.identity + cred.cred.identity_size);
    basic_credential.identity = mls_identity;
    mls::BasicCredential::type = (mls::CredentialType) cred.cred.type;
    std::variant<mls::BasicCredential> mls_cred = basic_credential;
    credential._cred = mls_cred;
    return credential;
}

bool mls_to_credential(mls::Credential *target, struct mls_credential *src) {
    if(target != nullptr && src != nullptr) {
        mls::BasicCredential credential = std::get<mls::BasicCredential>(target->_cred);
        
        return true;
    } else {
        return false;
    }
}

bool mls_to_basic_credential(mls::BasicCredential *target, struct mls_basic_credential *src) {

}