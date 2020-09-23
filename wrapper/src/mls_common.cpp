#include <iostream>
#include <cstring>
#include "mls_common.h"

bool mls_bytes_allocate(struct mls_bytes *bytes, size_t size) {
    bytes->size = size;
    bytes->data = (uint8_t*) malloc(size * sizeof(*bytes->data));
    return bytes;
}

bool mls_bytes_destroy(struct mls_bytes *bytes) {
    if(bytes != nullptr) {
        free(bytes->data);
        free(bytes);
        return true;
    } else {
        return true;
    }
}

bool mls_create_bytes(struct mls_bytes *target, uint8_t *data, size_t size) {
    target->data = data;
    target->size = size;
    return true;
}

bool mls_copy_bytes(struct mls_bytes *target, struct mls_bytes *src) {
    if(target != nullptr && src != nullptr) {
        memcpy(target, src->data, src->size * sizeof(*target->data));
        return true;
    } else {
        return false;
    }
}

void helloC(char name[]) {
    const mls_cipher_suite suite = mls_cipher_suite::X25519_AES128GCM_SHA256_Ed25519;
    std::cout << "Test";
}

bool mls_from_bytes(struct mls_bytes *target, mls::bytes *origin) {
    if(target != nullptr && origin != nullptr) {
        size_t size = origin->size();
        for(int i = 0; i < size; i++) {
            memcpy(&target->data[i], (uint8_t*)&origin->at(i), sizeof(uint8_t));
        }
        return true;
    } else {
        return false;
    }
}

bool mls_to_bytes(mls::bytes *target, struct mls_bytes *origin) {
    if(target != nullptr && origin != nullptr) {
        if(target->size() != origin->size) return false;
        for(int i = 0; i < origin->size; i++) {
            memcpy((uint8_t*)&target->at(i), &origin->data[i], sizeof(origin->data[i]));
        }
        return true;
    } else {
        return false;
    }
}
