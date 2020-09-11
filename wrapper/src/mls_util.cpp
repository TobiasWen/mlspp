#include "mls_util.h"

void printUint8Array(uint8_t *array, size_t array_size, char prefix[]) {
    for (int i = 0; i < array_size; i++) {
        printf("%s - index = %d | value = %u | address = %p\n", prefix, i, *(&array[i]), (&array[i]));
    }
}

struct mls_bytes from_mls_bytes(mls::bytes *bytes) {
    struct mls_bytes bytes1 = {};
    bytes1.size = bytes->size();
    uint8_t *data = (uint8_t*) malloc(bytes1.size * sizeof(*data));
    bytes1.data = data;
    for(int i = 0; i < bytes->size(); i++) {
        data[i] = (*bytes)[i];
    }
    return bytes1;
}