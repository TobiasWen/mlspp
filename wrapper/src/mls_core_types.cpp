#include <cstring>
#include "mls_core_types.h"
#include "mls/core_types.h"

struct mls_key_package mls_create_key_package(mls_cipher_suite suite,
                                              struct mls_HPKE_public_key HPKE_public_key,
                                              struct mls_credential credential,
                                              struct mls_signature_private_key signature_private_key) {
    auto mls_hpke_pub_key = mls_convert_to_HPKE_public_key(HPKE_public_key);
    auto mls_credential = mls_to_credential(credential);
    auto identity_priv = mls_convert_to_signature_private_key(signature_private_key);
    mls::KeyPackage package = mls::KeyPackage{ (mls::CipherSuite) suite, mls_hpke_pub_key, mls_credential, identity_priv };
    struct mls_key_package kpckg = {};
    kpckg.credential = mls_from_credential(package.credential);
    kpckg.init_key = mls_convert_from_HPKE_public_key(package.init_key);
    kpckg.cipher_suite = (mls_cipher_suite) package.cipher_suite;
    kpckg.extensions = mls_from_extension_list(package.extensions);
    kpckg.signature = (uint8_t*) &package.signature[0];
    kpckg.signature_size = (size_t) package.signature.size();
    kpckg.version = (mls_protocol_version) package.version;
    return kpckg;
}

struct mls_extension_list mls_from_extension_list(mls::ExtensionList extension_list) {
    struct mls_extension_list ext_list = {};
    //TODO:: This have to be freed somewhere!
    struct mls_extension *extensions = (struct mls_extension*) malloc(extension_list.extensions.size() * sizeof(*extensions));
    for(int i = 0; i < extension_list.extensions.size(); i++) {
        struct mls_extension extension = {};
        extension.type = (mls_extension_type) extension_list.extensions[i].type;
        extension.data = (uint8_t*) &extension_list.extensions[i].data[0];
        extension.data_size = extension_list.extensions[i].data.size();
        extensions[i] = extension;
    }
    ext_list.extensions = extensions;
    ext_list.extensions_size = extension_list.extensions.size();
    return ext_list;
}

struct mls_bytes mls_create_bytes(uint8_t *data, size_t size) {
    size_t size_bytes = size * sizeof(*data);
    uint8_t *heap_data = (uint8_t*) malloc(size_bytes);
    memcpy(heap_data, data, size_bytes);
    struct mls_bytes bytes = {};
    bytes.data = heap_data;
    bytes.size = size;
    return bytes;
}

mls::ExtensionList mls_to_extension_list(struct mls_extension_list extensions) {
    mls::ExtensionList mls_extensions = *new mls::ExtensionList();
    for(int i = 0; i < extensions.extensions_size; i++) {
        auto extension = *new mls::Extension();
        extension.type = (mls::ExtensionType) extensions.extensions[i].type;
        extension.data = mls::bytes(extensions.extensions[i].data, extensions.extensions[i].data + extensions.extensions[i].data_size);
        mls_extensions.extensions.push_back(extension);
    }
    return mls_extensions;
}

mls::KeyPackage mls_to_key_package(struct mls_key_package key_package) {
    auto *package = new mls::KeyPackage();
    mls::HPKEPublicKey init_key = mls_convert_to_HPKE_public_key(key_package.init_key);
    mls::Credential credential = mls_to_credential(key_package.credential);
    mls::ExtensionList extensions = mls_to_extension_list(key_package.extensions);
    mls::bytes signature(key_package.signature, key_package.signature + key_package.signature_size);
    package->version = (mls::ProtocolVersion) key_package.version;
    package->cipher_suite = (mls::CipherSuite) key_package.cipher_suite;
    package->init_key = init_key;
    package->credential = credential;
    package->extensions = extensions;
    package->signature = signature;
    return *package;
}

struct mls_bytes mls_from_bytes(mls::bytes bytes) {
    return mls_create_bytes((uint8_t*)&bytes[0], bytes.size());
}