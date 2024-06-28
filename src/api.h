#pragma once

#include <vector>

#include <LIEF/LIEF.hpp>

using binPtr_t = std::unique_ptr<LIEF::ELF::Binary>;
using symPtr_t = std::shared_ptr<LIEF::ELF::Symbol>;
using relPtr_t = std::shared_ptr<LIEF::ELF::Relocation>;


// listSyms lists all symbols contained in a binary
void listSyms(const binPtr_t&);

// substituteCall replaces a call to a symbol by a call to another symbol
// in binary's .text section
bool substituteCall(binPtr_t&, const std::string&, const std::string&);

// extractFunctionOps finds a function definition in .text and returns its assembly operations
// as a byte vector
std::vector<uint8_t> extractFunctionOps(binPtr_t&, const std::string&);

// getSectionIdx returns the index of the section in the binary
unsigned getSectionIdx(binPtr_t&, const std::string&);

// injectFromLib inject symbols from a shared library as static symbols
// in the binary. Symbols are added to the binary symtab and function code
// to the .text section
bool injectFromLib(binPtr_t& exeBin, binPtr_t& libBin);

// addDynSym adds an entry in the ".dynsym" section of the binary
symPtr_t addDynSym(binPtr_t&, const std::string&);

// addReloc adds an entry to ".rel.plt" for the specified symbol and call address
relPtr_t addReloc(binPtr_t&, const symPtr_t&, uint64_t);

bool substituteCallDyn(binPtr_t& bin, const std::string& sym1_name, const std::string& sym2_name);