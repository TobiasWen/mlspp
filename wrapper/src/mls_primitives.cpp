#include "mls_primitives.h"

bool mls_generate_random_bytes(struct mls_bytes *target, size_t size) {
    if(target != nullptr) {
        mls::bytes random_bytes = mls::random_bytes(size);
        mls_from_bytes(target, &random_bytes);
        return true;
    } else {
        return false;
    }
}
