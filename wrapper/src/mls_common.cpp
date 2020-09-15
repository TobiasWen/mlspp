#include <iostream>
#include <cstring>
#include "mls_common.h"

bool mls_create_bytes(struct mls_bytes *target, uint8_t *data, size_t size) {
    target->data = data;
    target->size = size;
    return true;
}

void helloC(char name[]) {
    const mls_cipher_suite suite = mls_cipher_suite::X25519_AES128GCM_SHA256_Ed25519;
    std::cout << "Test";
}

bool mls_from_bytes(struct mls_bytes *target, mls::bytes *origin) {
    if(target != nullptr && origin != nullptr) {
        size_t size = origin->size();
        memcpy(target, (uint8_t*)&origin[0], size * sizeof(uint8_t));
        return true;
    } else {
        return false;
    }
}

bool mls_to_bytes(mls::bytes *target, struct mls_bytes *origin) {
    if(target != nullptr && origin != nullptr) {
        if(target->size() != origin->size) return false;
        for(int i = 0; i < origin->size; i++) {
            memcpy(&target[i], &origin[i].data, origin->size);
        }
        return true;
    } else {
        return false;
    }
}
