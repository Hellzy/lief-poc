#include <LIEF/LIEF.hpp>
#include <iostream>

using binPtr_t = std::unique_ptr<LIEF::ELF::Binary>;

void substituteCall(binPtr_t& bin, const std::string& sym1_name, const std::string& sym2_name) {
    auto* sym1 = bin->get_symbol(sym1_name);
    auto* sym2 = bin->get_symbol(sym2_name);


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

}

int main() {
    auto bin = LIEF::ELF::Parser::parse("../bin/hello");
    std::string sym_name1 = "_Z5hellov";
    std::string sym_name2 = "_Z7goodbyev";

    substituteCall(bin, sym_name1, sym_name2);

    LIEF::ELF::Builder builder(*bin);
    builder.build();
    builder.write("modified");

    return  0;
}