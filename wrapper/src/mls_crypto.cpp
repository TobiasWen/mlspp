#include "mls_crypto.h"
#include "mls/crypto.h"

bool mls_signature_private_key_instantiate(struct mls_signature_private_key *target, mls_cipher_suite suite, size_t size) {
    if(target != nullptr) {
        mls_bytes_allocate(&target->data, size);
        mls_bytes_allocate(&target->public_key.data, size);
        mls_generate_mls_signature_private_key(target, suite);
        return true;
    } else {
        return false;
    }
}

bool mls_signature_private_key_destroy(struct mls_signature_private_key *target) {
    if(target != nullptr) {
        mls_bytes_destroy(&target->data);
        mls_bytes_destroy(&target->public_key.data);
        free(target);
        return true;
    } else {
        return false;
    }
}

bool mls_signature_public_key_instantiate(struct mls_signature_public_key *target, mls_cipher_suite suite, size_t size) {
    mls_bytes_allocate(&target->data, size);

}
bool mls_signature_public_key_destroy(struct mls_signature_public_key *target);

bool mls_generate_mls_signature_private_key(struct mls_signature_private_key *target, mls_cipher_suite suite) {
    if(target != nullptr) {
        auto priv = mls::SignaturePrivateKey::generate(static_cast<mls::CipherSuite>(suite));
        mls_convert_from_signature_private_key(target, &priv);
        return true;
    } else {
        return false;
    }
}

bool mls_hpke_private_key_allocate(struct mls_HPKE_private_key *target, size_t key_size) {
    if(target != nullptr) {
        mls_bytes_allocate(&target->data, key_size);
        mls_hpke_public_key_allocate(&target->public_key, key_size);
        return true;
    } else {
        return false;
    }
}

bool mls_HPKE_private_key_destroy(struct mls_HPKE_private_key *target) {
    if(target != nullptr) {
        mls_bytes_destroy(&target->data);
        mls_bytes_destroy(&target->public_key.data);
        free(target);
        return true;
    } else {
        return false;
    }
}

bool mls_hpke_public_key_allocate(struct mls_HPKE_public_key *target, size_t key_size) {
    if(target != nullptr) {
        mls_bytes_allocate(&target->data, key_size);
        return true;
    } else {
        return false;
    }
}

bool mls_hpke_public_key_destroy(struct mls_HPKE_public_key *target) {
    if(target != nullptr) {
        mls_bytes_destroy(&target->data);
        free(target);
        return true;
    } else {
        return false;
    }
}

bool mls_derive_HPKE_private_key(struct mls_HPKE_private_key *target, mls_cipher_suite suite, mls_bytes *secret) {
    if(target != nullptr && secret != nullptr) {
        mls::bytes mls_init_secret(secret->data, secret->data + secret->size);
        auto HPKE_key = mls::HPKEPrivateKey::derive(static_cast<mls::CipherSuite>(suite), mls_init_secret);
        mls_convert_from_HPKE_private_key(target, &HPKE_key);
        return true;
    } else {
        return false;
    }
}
// Signature Private/Public key type conversions

bool mls_convert_from_signature_private_key(mls_signature_private_key *target, mls::SignaturePrivateKey *src) {
    if(target != nullptr && src != nullptr) {
        target->signature_scheme = (mls_signature_scheme) src->_scheme;
        target->cipher_suite = (mls_cipher_suite) src->_suite;
        mls_from_bytes(&target->data, &src->_data);
        mls::SignaturePublicKey pub_key = src->public_key();
        mls_convert_from_signature_public_key(&target->public_key, &pub_key);
        return true;
    } else {
        return true;
    }
}

bool mls_convert_to_signature_private_key(mls::SignaturePrivateKey *target, mls_signature_private_key *src) {
    if(target != nullptr && src != nullptr) {
        mls_to_bytes(&target->_data, &src->data);
        mls_to_bytes(&target->_pub_data, &src->public_key.data);
        target->_suite = (mls::CipherSuite) src->cipher_suite;
        target->_scheme = (mls::SignatureScheme) src->signature_scheme;
        return true;
    } else {
        return true;
    }
}

bool mls_convert_from_signature_public_key(mls_signature_public_key *target, mls::SignaturePublicKey *src) {
    if(target != nullptr && src != nullptr) {
        target->signature_scheme = (mls_signature_scheme) src->_scheme;
        mls_from_bytes(&target->data, &src->_data);
        return true;
    } else {
        return false;
    }
}

bool mls_convert_to_signature_public_key(mls::SignaturePublicKey *target, mls_signature_public_key *src) {
    if(target != nullptr && src != nullptr) {
        mls_to_bytes(&target->_data, &src->data);
        target->_scheme = (mls::SignatureScheme) src->signature_scheme;
        return true;
    } else {
        return false;
    }
}

// HPKE Private/Public key type conversions
bool mls_convert_from_HPKE_private_key(mls_HPKE_private_key *target, mls::HPKEPrivateKey *src) {
    if(target != nullptr && src != nullptr) {
        mls_from_bytes(&target->data, &src->_data);
        mls::HPKEPublicKey pub_key = src->public_key();
        mls_convert_from_HPKE_public_key(&target->public_key, &pub_key);
        return true;
    } else {
        return false;
    }
}

bool mls_convert_to_HPKE_private_key(mls::HPKEPrivateKey *target, mls_HPKE_private_key *src) {
    if(target != nullptr && src != nullptr) {
        mls_to_bytes(&target->_data, &src->data);
        mls_to_bytes(&target->_pub_data, &src->public_key.data);
        return true;
    } else {
        return false;
    }
}

bool mls_convert_from_HPKE_public_key(mls_HPKE_public_key *target, mls::HPKEPublicKey *src) {
    if(target != nullptr && src != nullptr) {
        mls_from_bytes(&target->data, &src->data);
        return true;
    } else {
        return false;
    }
}

bool mls_convert_to_HPKE_public_key(mls::HPKEPublicKey *target, mls_HPKE_public_key *src) {
    if(target != nullptr && src != nullptr) {
        mls_to_bytes(&target->data, &src->data);
        return true;
    } else {
        return false;
    }
}