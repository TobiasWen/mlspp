#include "mls_primitives.h"
#include "mls_util.h"

struct mls_bytes mls_generate_random_bytes(size_t size) {
    mls::bytes random_bytes = mls::random_bytes(size);
   return from_mls_bytes(&random_bytes);
}

