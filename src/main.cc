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

std::vector<uint8_t> extract_function(binPtr_t& bin, const std::string& fName) {
    std::vector<uint8_t> vec{};
    auto* sym = bin->get_symbol(fName);
    if (!sym) {
        std::cerr << "Couldn't find sym '" << fName << "'\n";
        return vec;
    }
    
    auto section = bin->section_from_virtual_address(sym->value());
    if (!section) {
        std::cerr << "Couldn't find section\n";
        return vec;
    }

    uint64_t offset = sym->value() - section->virtual_address();
    vec = std::vector<uint8_t>(section->content().begin()+offset, section->content().begin() + offset + sym->size());
    return vec;
}

unsigned getSectionIdx(binPtr_t& bin, const std::string& sectionName) {
    auto sections = bin->sections();
    for (auto i = 0u; i < sections.size(); ++i) {
        if (sections[i].name() == sectionName)
            return i;
    }

    return 0;
}

bool injectFromLib(binPtr_t& exeBin, binPtr_t& libBin) {
    auto* sym = libBin->get_symbol("_Z5hellov");
    auto funcOps = extract_function(libBin, "_Z5hellov");

    /*
        // Create new section for the function
        LIEF::ELF::Section section(".mysupernewsection", LIEF::ELF::Section::TYPE::PROGBITS);
        section.content(funcOps);
        auto *newSection = exeBin->add(section);

        if (!newSection) {
            std::cerr << "Returned section is nill after adding to binary\n";
            return false;
        }
    */

   auto* text = exeBin->text_section();
   if (!text) {
    std::cerr << "Couldn't find text section\n";
    return false;
   }
   auto content = text->content();
   auto newAddr = text->virtual_address() + content.size();
   auto contentVec = std::vector<uint8_t>(content.begin(), content.end());
   contentVec.insert(contentVec.end(), funcOps.begin(), funcOps.end());
   text->content(contentVec);
   text->size(text->size() + funcOps.size());

    // Create new symbol entry for the function
    LIEF::ELF::Symbol newSym(sym->name());
    newSym.value(newAddr);
    newSym.size(funcOps.size());
    newSym.type(LIEF::ELF::Symbol::TYPE::FUNC);
    newSym.binding(LIEF::ELF::Symbol::BINDING::GLOBAL);
    newSym.shndx(getSectionIdx(exeBin, ".text"));
    
    auto addedSym = exeBin->add_symtab_symbol(newSym);
    std::cout << "Added '" << sym->name() << "'\n";
    std::cout << "Addr: " << sym->value() << "\n";

    return true;
}

int main() {
    auto libBin = LIEF::ELF::Parser::parse("lib/libhello.so");
    auto exeBin = LIEF::ELF::Parser::parse("patchee/patchee");

    std::cout << std::boolalpha << injectFromLib(exeBin, libBin) << '\n';

    LIEF::ELF::Builder builder(*exeBin);
    builder.build();
    builder.write("modified");

    return  0;
}