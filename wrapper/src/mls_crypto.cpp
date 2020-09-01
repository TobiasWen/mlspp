#include "mls_crypto.h"
#include "mls/crypto.h"

mls_signature_private_key mls_generate_mls_signature_private_key(mls_cipher_suite suite) {
    auto priv = mls::SignaturePrivateKey::generate(static_cast<mls::CipherSuite>(suite));
    return convert_from_signature_private_key(priv);
}

struct mls_signature_public_key mls_get_signature_public_key_from_private_key(struct mls_signature_private_key private_key) {
    struct mls_signature_public_key wrapped_pub;
    mls::SignaturePublicKey mls_pub = convert_to_signature_private_key(private_key).public_key();
    wrapped_pub.signature_scheme = static_cast<mls_signature_scheme>(mls_pub.signature_scheme());
    wrapped_pub.data = (uint8_t*)&mls_pub._data[0];
    wrapped_pub.data_size = mls_pub._data.size();
    return wrapped_pub;
}

mls_signature_private_key convert_from_signature_private_key(const mls::SignaturePrivateKey private_key) {
    struct mls_signature_private_key key{};
    key.signature_scheme = static_cast<mls_signature_scheme>(private_key._scheme);
    key.cipher_suite = static_cast<mls_cipher_suite>(private_key._suite);
    key.data = (uint8_t*)&private_key._data[0];
    key.data_size = private_key._data.size();
    key.pub_data = (uint8_t*)&private_key._pub_data[0];
    key.pub_data_size = private_key._pub_data.size();
    return key;
}

mls::SignaturePrivateKey convert_to_signature_private_key(const mls_signature_private_key private_key) {
    mls::bytes data(private_key.data, private_key.data + private_key.data_size);
    return mls::SignaturePrivateKey::derive(static_cast<mls::CipherSuite>(private_key.cipher_suite), data);
}

mls::SignaturePublicKey convert_to_signature_public_key(const mls_signature_public_key public_key) {
    mls::bytes data(public_key.data, public_key.data + public_key.data_size);
    mls::SignaturePublicKey pub_key = mls::SignaturePublicKey();
    pub_key.set_signature_scheme(static_cast<mls::SignatureScheme>(public_key.signature_scheme));
    pub_key._data = data;
    return pub_key;
}

mls_signature_public_key convert_from_signature_public_key(const mls::SignaturePublicKey public_key) {
    struct mls_signature_public_key pub_key{};
    pub_key.signature_scheme = static_cast<mls_signature_scheme>(public_key.signature_scheme());
    pub_key.data = (uint8_t*)&public_key._data[0];
    pub_key.data_size = public_key._data.size();
    return pub_key;
}
