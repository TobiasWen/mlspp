#include <hpke/random.h>

#include "openssl_common.h"

#include <openssl/rand.h>

namespace hpke {

bytes
random_bytes(size_t size)
{
  auto rand = bytes(size);
  if (1 != RAND_bytes(rand.data(), size)) {
    throw openssl_error();
  }
  return rand;
}

} // namespace hpke
