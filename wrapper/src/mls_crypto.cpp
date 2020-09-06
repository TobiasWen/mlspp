#include "string.h"
#include "mls_crypto.h"
#include "mls/crypto.h"

mls_signature_private_key mls_generate_mls_signature_private_key(mls_cipher_suite suite) {
    auto priv = mls::SignaturePrivateKey::generate(static_cast<mls::CipherSuite>(suite));
    return mls_convert_from_signature_private_key(priv);
}

struct mls_signature_public_key mls_get_signature_public_key_from_private_key(struct mls_signature_private_key private_key) {
    struct mls_signature_public_key wrapped_pub;
    mls::SignaturePublicKey mls_pub = mls_convert_to_signature_private_key(private_key).public_key();
    wrapped_pub.signature_scheme = static_cast<mls_signature_scheme>(mls_pub.signature_scheme());
    wrapped_pub.data = (uint8_t*)&mls_pub._data[0];
    wrapped_pub.data_size = mls_pub._data.size();
    return wrapped_pub;
}

bool mls_get_signature_public_key_from_private_key_test(struct mls_signature_private_key private_key, struct mls_signature_public_key *result) {
    mls::SignaturePublicKey mls_pub = mls_convert_to_signature_private_key(private_key).public_key();
    result->signature_scheme = static_cast<mls_signature_scheme>(mls_pub.signature_scheme());
    memcpy(result->data, private_key.data, 64);
    result->data_size = mls_pub._data.size();
    return true;
}

struct mls_HPKE_private_key mls_derive_HPKE_private_key(mls_cipher_suite suite, uint8_t *secret, size_t secret_size) {
    mls::bytes mls_init_secret(secret, secret + secret_size);
    auto HPKE_key = mls::HPKEPrivateKey::derive(static_cast<mls::CipherSuite>(suite), mls_init_secret);
    return mls_convert_from_HPKE_private_key(HPKE_key);
}

// Signature Private/Public key type conversions

mls_signature_private_key mls_convert_from_signature_private_key(const mls::SignaturePrivateKey private_key) {
    struct mls_signature_private_key key{};
    key.signature_scheme = static_cast<mls_signature_scheme>(private_key._scheme);
    key.cipher_suite = static_cast<mls_cipher_suite>(private_key._suite);
    key.data = (uint8_t*)&private_key._data[0];
    key.data_size = private_key._data.size();
    key.pub_data = (uint8_t*)&private_key._pub_data[0];
    key.pub_data_size = private_key._pub_data.size();
    return key;
}

mls::SignaturePrivateKey mls_convert_to_signature_private_key(const mls_signature_private_key private_key) {
    mls::bytes data(private_key.data, private_key.data + private_key.data_size);
    return mls::SignaturePrivateKey::derive(static_cast<mls::CipherSuite>(private_key.cipher_suite), data);
}

mls::SignaturePublicKey mls_convert_to_signature_public_key(const mls_signature_public_key public_key) {
    mls::bytes data(public_key.data, public_key.data + public_key.data_size);
    mls::SignaturePublicKey pub_key = mls::SignaturePublicKey();
    pub_key.set_signature_scheme(static_cast<mls::SignatureScheme>(public_key.signature_scheme));
    pub_key._data = data;
    return pub_key;
}

mls_signature_public_key mls_convert_from_signature_public_key(const mls::SignaturePublicKey public_key) {
    struct mls_signature_public_key pub_key{};
    pub_key.signature_scheme = static_cast<mls_signature_scheme>(public_key.signature_scheme());
    pub_key.data = (uint8_t*)&public_key._data[0];
    pub_key.data_size = public_key._data.size();
    return pub_key;
}

// HPKE Private/Public key type conversions
mls_HPKE_private_key mls_convert_from_HPKE_private_key(mls::HPKEPrivateKey private_key) {
    struct mls_HPKE_private_key mls_private_key = {nullptr};
    mls_private_key.data = (uint8_t*)&private_key._data[0];
    mls_private_key.data_size = private_key._data.size();
    struct mls_HPKE_public_key public_key = mls_convert_from_HPKE_public_key(private_key.public_key());
    mls_private_key.pub_data = public_key.data;
    mls_private_key.pub_data_size = public_key.data_size;
    return mls_private_key;
}

mls::HPKEPrivateKey mls_convert_to_HPKE_private_key(mls_HPKE_private_key private_key) {
    mls::bytes data(private_key.data, private_key.data + private_key.data_size);
    mls::bytes pub_data(private_key.pub_data, private_key.pub_data + private_key.pub_data_size);
    mls::HPKEPrivateKey mls_private_key = mls::HPKEPrivateKey();
    mls_private_key._data = data;
    mls_private_key._pub_data = pub_data;
    return mls_private_key;
}

mls_HPKE_public_key mls_convert_from_HPKE_public_key(mls::HPKEPublicKey public_key) {
    struct mls_HPKE_public_key mls_public_key = {nullptr};
    mls_public_key.data = (uint8_t*)&public_key.data[0];
    mls_public_key.data_size = public_key.data.size();
    return mls_public_key;
}

mls::HPKEPublicKey mls_convert_to_HPKE_public_key(mls_HPKE_public_key public_key) {
    mls::bytes data(public_key.data, public_key.data + public_key.data_size);
    mls::HPKEPublicKey mls_public_key = mls::HPKEPublicKey();
    mls_public_key.data = data;
    return mls_public_key;
}
