#include <unistd.h>
#include "mls_util.h"
#include <cstdio>
#include <cstdint>
#include <cinttypes>
#include <cstring>

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

bool points_to_heap(void* init_brk, void* pointer){
    void* cur_brk = sbrk(0);
    return ((init_brk <= pointer) && (pointer <= cur_brk));
}


void get_heap_bounds(uint64_t* heap_start, uint64_t* heap_end){
    FILE *stream;
    char *line = NULL;
    size_t len = 0;
    ssize_t nread;

    stream = fopen("/proc/self/maps", "r");

    while ((nread = getline(&line, &len, stream)) != -1) {
        if (strstr(line, "[heap]")){
            sscanf(line, "%" SCNx64 "-%" SCNx64 "", heap_start, heap_end);
            break;
        }
    }

    free(line);
    fclose(stream);
}

bool is_heap_var(void* pointer){
    uint64_t heap_start = 0;
    uint64_t heap_end = 0;
    get_heap_bounds(&heap_start, &heap_end);

    if (pointer >= (void*)heap_start && pointer <= (void*)heap_end){
        return true;
    }
    return false;
}