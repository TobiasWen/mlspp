#include "mls_primitives.h"

struct mls_random_bytes mls_generate_random_bytes(size_t size) {
    mls::bytes random_bytes = mls::random_bytes(size);
    struct mls_random_bytes bytes = {0};
    bytes.bytes = (uint8_t*) &random_bytes[0];
    bytes.size = random_bytes.size();
    return bytes;
}

