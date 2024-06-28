#include <iostream>

#include <LIEF/LIEF.hpp>

#include "api.h"

int main()
{
    auto exeBin = LIEF::ELF::Parser::parse("patchee/patchee");

    substituteCallDyn(exeBin, "_Z5printv", "_Z5hellov");

    LIEF::ELF::Builder::config_t cfg;
    cfg.force_relocate = true;
    cfg.rela = true;
    LIEF::ELF::Builder builder(*exeBin);
    builder.set_config(cfg);
    builder.build();
    builder.write("modified");
}
