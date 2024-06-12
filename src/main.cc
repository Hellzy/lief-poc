#include <LIEF/LIEF.h>
#include <LIEF/LIEF.hpp>
#include <iostream>

LIEF::MachO::Binary* getBin(const std::string& path) {
    auto fatBin = LIEF::MachO::Parser::parse(path);
    return fatBin->front();
}

int main() {
    auto* bin = getBin("../bin/hello");
    std::cout << "Bin: " << bin->fileset_name() << '\n';
    for (const auto sym : bin->symbols())
        std::cout << "- " << sym.name() << '\n';
}