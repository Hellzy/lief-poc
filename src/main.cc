#include <algorithm>
#include <iostream>
#include <utility>
#include <vector>

#include <LIEF/LIEF.hpp>

using binPtr_t = std::unique_ptr<LIEF::ELF::Binary>;

void listSyms(const binPtr_t& bin) {
    for (const auto& sym : bin->symbols())
        std::cout << sym.name() << '\n';
}

bool substituteCall(binPtr_t& bin, const std::string& sym1_name, const std::string& sym2_name) {
    auto* sym1 = bin->get_symbol(sym1_name);
    auto* sym2 = bin->get_symbol(sym2_name);

    if (!sym1) {
        std::cerr << "Couldn't find '" << sym1_name << "'\n";
        return false;
    }
    if (!sym2) {
        std::cerr << "Couldn't find '" << sym2_name << "'\n";
        return false;
    }


    auto* text = bin->get_section(".text");
    auto text_addr = text->virtual_address();
    auto text_content = text->content();

    for (auto i = 0u; i < text_content.size(); ++i) {
        auto instr = text_content[i];
        if (instr != 0xE8)
            continue;

        auto ip_addr = text_addr + i;
        auto jmp_offset = *((int32_t*)&text_content[i+1]);
        // CALL (0xE8) is encoded on 5 bytes, 1 for instruction, 4 for offset
        uint32_t call_addr = ip_addr + jmp_offset + 5;

        if (call_addr == sym1->value()) {
            int32_t fnDiff = sym2->value() - sym1->value();
            *(uint32_t *)(&text_content[i + 1]) = jmp_offset + fnDiff;
        }
    }

    return true;

}

void hookGot(binPtr_t& bin, const std::string& sym1_name, const std::string& sym2_name) {
    auto* got = bin->get_section(".plt.got");
    if (!got) {
        return;
    }
    auto sym2 =  bin->get_symbol(sym2_name);
    bin->patch_pltgot(sym1_name, sym2->value());
}

void switchSyms(binPtr_t& bin, const std::string& sym1_name, const std::string& sym2_name) {
    auto* sym1 = bin->get_symtab_symbol(sym1_name);
    auto* sym2 = bin->get_symtab_symbol(sym2_name);

    bin->remove_symtab_symbol(sym1_name);
    bin->remove_symtab_symbol(sym2_name);

}

int main() {
    //auto bin = LIEF::ELF::Parser::parse("../bin/hello");
    //std::string sym_name1 = "_Z5hellov";
    //std::string sym_name2 = "_Z7goodbyev";

    auto bin = LIEF::ELF::Parser::parse("../go/app");
    std::string sym_name1 = "math/rand.Int";
    std::string sym_name2 = "main.Int";

    //hookGot(bin, sym_name1, sym_name2);
    //switchSyms(bin, sym_name1, sym_name2);
    if (!substituteCall(bin, sym_name1, sym_name2))
        listSyms(bin);

    LIEF::ELF::Builder builder(*bin);
    builder.build();
    builder.write("modified");

    return  0;
}