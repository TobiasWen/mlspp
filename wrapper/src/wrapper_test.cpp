#include "wrapper_test.h"

#include <iostream>

void hello(std::string name) {
    std::cout << "Hello, " << name << "!" << std::endl;
}

void helloC(char name[]) {
    hello(name);
}