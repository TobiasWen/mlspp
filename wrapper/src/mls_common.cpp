#include "mls_common.h"
#include "stdio.h"
#include <iostream>
void helloC(char name[]) {
    const mls_cipher_suite suite = mls_cipher_suite::X25519_AES128GCM_SHA256_Ed25519;
    std::cout << "Test";
}
