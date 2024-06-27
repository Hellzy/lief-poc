#include <iostream>

#include <LIEF/LIEF.hpp>

#include "api.h"


int main() {
    auto libBin = LIEF::ELF::Parser::parse("lib/libhello.so");
    auto exeBin = LIEF::ELF::Parser::parse("patchee/patchee");

    std::cout << std::boolalpha << injectFromLib(exeBin, libBin) << '\n';

    LIEF::ELF::Builder builder(*exeBin);
    builder.build();
    builder.write("modified");

    return  0;
}