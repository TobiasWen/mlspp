#pragma once

#include <bytes/bytes.h>
#include <hpke/signature.h>

#include <memory>

using namespace bytes_ns;

namespace hpke {

struct Certificate
{
private:
  struct ParsedCertificate;
  std::unique_ptr<ParsedCertificate> parsed_cert;

public:
  explicit Certificate(const bytes& der);
  Certificate() = delete;
  Certificate(const Certificate& other);
  ~Certificate();

  bool valid_from(const Certificate& parent);

  const Signature::ID public_key_algorithm;
  const std::unique_ptr<Signature::PublicKey> public_key;
  const bytes raw;
};

} // namespace hpke
