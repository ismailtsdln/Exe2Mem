#include <cassert>
#include <cstring>
#include <iostream>
#include <vector>

#include "../../core/pe_parser/pe_parser.hpp"
#include "../../core/pe_validator/pe_validator.hpp"

using namespace exe2mem::core;

void test_pe_parser_basic() {
  std::vector<uint8_t> fake_pe(4096, 0);

  // Setup DOS header
  IMAGE_DOS_HEADER *dos = reinterpret_cast<IMAGE_DOS_HEADER *>(fake_pe.data());
  dos->e_magic = 0x5A4D;
  dos->e_lfanew = 0x40;

  // NT signature
  uint32_t *pe_sig = reinterpret_cast<uint32_t *>(fake_pe.data() + 0x40);
  *pe_sig = 0x00004550;

  // NT headers (x64)
  IMAGE_NT_HEADERS64 *nt64 =
      reinterpret_cast<IMAGE_NT_HEADERS64 *>(fake_pe.data() + 0x40);
  nt64->FileHeader.Machine = 0x8664;
  nt64->FileHeader.NumberOfSections = 1;
  nt64->FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER64);
  nt64->OptionalHeader.Magic = 0x020B; // PE32+
  nt64->OptionalHeader.SizeOfImage = 0x2000;
  nt64->OptionalHeader.ImageBase = 0x140000000;

  // Section header
  IMAGE_SECTION_HEADER *section = reinterpret_cast<IMAGE_SECTION_HEADER *>(
      fake_pe.data() + 0x40 + 4 + sizeof(IMAGE_FILE_HEADER) +
      sizeof(IMAGE_OPTIONAL_HEADER64));
  std::memcpy(section->Name, ".text", 5);
  section->VirtualAddress = 0x1000;
  section->Misc.VirtualSize = 0x1000;
  section->PointerToRawData = 0x200;
  section->SizeOfRawData = 0x200;

  PeParser parser(fake_pe);
  assert(parser.parse());
  assert(parser.is_x64());
  assert(parser.get_section_header(0) != nullptr);
  assert(std::string(reinterpret_cast<const char *>(
             parser.get_section_header(0)->Name)) == ".text");
  assert(parser.get_rva_to_offset(0x1100) == 0x200 + 0x100);

  std::cout << "test_pe_parser_basic passed!" << std::endl;
}

void test_pe_validator() {
  std::vector<uint8_t> fake_pe(4096, 0);

  // Setup DOS header
  IMAGE_DOS_HEADER *dos = reinterpret_cast<IMAGE_DOS_HEADER *>(fake_pe.data());
  dos->e_magic = 0x5A4D;
  dos->e_lfanew = 0x40;

  // NT headers
  uint32_t *pe_sig = reinterpret_cast<uint32_t *>(fake_pe.data() + 0x40);
  *pe_sig = 0x00004550;

  IMAGE_NT_HEADERS64 *nt64 =
      reinterpret_cast<IMAGE_NT_HEADERS64 *>(fake_pe.data() + 0x40);
  nt64->FileHeader.Machine = 0x8664;
  nt64->FileHeader.NumberOfSections = 0; // Invalid for validator

  PeParser parser(fake_pe);
  assert(parser.parse());

  PeValidator validator(parser);
  assert(!validator.validate());
  assert(!validator.get_errors().empty());

  std::cout << "test_pe_validator passed!" << std::endl;
}

int main() {
  try {
    test_pe_parser_basic();
    test_pe_validator();
  } catch (const std::exception &e) {
    std::cerr << "Test failed: " << e.what() << std::endl;
    return 1;
  }
  return 0;
}
