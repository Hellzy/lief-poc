#include <iostream>

#include <LIEF/LIEF.hpp>

#include "api.h"


int main() {
    auto exeBin = LIEF::ELF::Parser::parse("../go/app");
    auto sym1 = "math/rand.Int";
    auto sym2 = "main.Int";

    if (!substituteCall(exeBin, sym1, sym2)) {
        std::cerr << "Could not substitute call to '" << sym1 << "' by call to '" << sym2 << "'\n";
        return 1;
    }

    LIEF::ELF::Builder builder(*exeBin);
    builder.build();
    builder.write("modified");

    return  0;
}