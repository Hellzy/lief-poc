#pragma once

#include <vector>

#include <LIEF/LIEF.hpp>

using binPtr_t = std::unique_ptr<LIEF::ELF::Binary>;


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