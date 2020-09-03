#include "mls_credential.h"
#include "mls/crypto.h"

struct mls_credential mls_create_basic_credential(uint8_t *identity, uint32_t identity_size, struct mls_signature_public_key public_key) {
    mls::bytes mls_identity(identity, identity + identity_size);
    mls::SignaturePublicKey mls_pub_key = mls_convert_to_signature_public_key(public_key);
    mls::Credential basic_cred = mls::Credential::basic(mls_identity, mls_pub_key);
    return mls_from_credential(basic_cred);
}

struct mls_credential mls_from_credential(mls::Credential cred) {
    struct mls_credential credential = {nullptr};
    struct mls_basic_credential basic_credential = {nullptr};
    mls::BasicCredential mls_basic_credential = std::get<mls::BasicCredential>(cred._cred);
    basic_credential.public_key = mls_convert_from_signature_public_key(mls_basic_credential.public_key);
    basic_credential.identity = (uint8_t*) &mls_basic_credential.identity[0];
    basic_credential.identity_size = mls_basic_credential.identity.size();
    basic_credential.type = static_cast<mls_credential_type>(mls::BasicCredential::type); //TODO: Does this work?
    credential.cred = basic_credential;
    return credential;
}