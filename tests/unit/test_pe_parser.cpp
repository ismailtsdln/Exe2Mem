#include "core/pe_parser/pe_parser.hpp"
#include <cassert>
#include <cstring>
#include <iostream>
#include <vector>

using namespace exe2mem::core;

void test_pe_parser_basic() {
  std::vector<uint8_t> fake_pe(1024, 0);
  IMAGE_DOS_HEADER *dos = reinterpret_cast<IMAGE_DOS_HEADER *>(fake_pe.data());
  dos->e_magic = 0x5A4D; // MZ
  dos->e_lfanew = 0x40;

  uint32_t *pe_sig = reinterpret_cast<uint32_t *>(fake_pe.data() + 0x40);
  *pe_sig = 0x00004550; // PE\0\0

  IMAGE_FILE_HEADER *file =
      reinterpret_cast<IMAGE_FILE_HEADER *>(fake_pe.data() + 0x44);
  file->Machine = 0x8664; // x64
  file->NumberOfSections = 1;
  file->SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER64);

  IMAGE_SECTION_HEADER *section = reinterpret_cast<IMAGE_SECTION_HEADER *>(
      fake_pe.data() + 0x44 + sizeof(IMAGE_FILE_HEADER) +
      sizeof(IMAGE_OPTIONAL_HEADER64));
  memcpy(section->Name, ".text", 5);
  section->VirtualAddress = 0x1000;
  section->Misc.VirtualSize = 0x1000;
  section->PointerToRawData = 0x200;
  section->SizeOfRawData = 0x1000;

  PeParser parser(fake_pe);
  assert(parser.parse());
  assert(parser.is_x64());
  assert(parser.get_section_header(0) != nullptr);
  assert(parser.get_rva_to_offset(0x1500) == 0x200 + 0x500);

  // Verify empty imports/relocs for now
  assert(parser.get_imports().empty());
  assert(parser.get_relocations().empty());

  std::cout << "test_pe_parser_basic passed!" << std::endl;
}

void test_pe_parser_imports() {
  std::vector<uint8_t> fake_pe(4096, 0);
  // ... setup DOS/NT headers ...
  IMAGE_DOS_HEADER *dos = reinterpret_cast<IMAGE_DOS_HEADER *>(fake_pe.data());
  dos->e_magic = 0x5A4D;
  dos->e_lfanew = 0x40;

  uint32_t *pe_sig = reinterpret_cast<uint32_t *>(fake_pe.data() + 0x40);
  *pe_sig = 0x00004550;

  IMAGE_NT_HEADERS64 *nt64 =
      reinterpret_cast<IMAGE_NT_HEADERS64 *>(fake_pe.data() + 0x40);
  nt64->FileHeader.Machine = 0x8664;
  nt64->FileHeader.NumberOfSections = 1;
  nt64->FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER64);

  // Data directory for imports
  nt64->OptionalHeader.DataDirectory[1].VirtualAddress = 0x2000;
  nt64->OptionalHeader.DataDirectory[1].Size =
      sizeof(IMAGE_IMPORT_DESCRIPTOR) * 2;

  // Section mapping
  IMAGE_SECTION_HEADER *section = reinterpret_cast<IMAGE_SECTION_HEADER *>(
      fake_pe.data() + 0x40 + 4 + sizeof(IMAGE_FILE_HEADER) +
      sizeof(IMAGE_OPTIONAL_HEADER64));
  memcpy(section->Name, ".idata", 7);
  section->VirtualAddress = 0x2000;
  section->Misc.VirtualSize = 0x1000;
  section->PointerToRawData = 0x1000;
  section->SizeOfRawData = 0x1000;

  // Import descriptor at raw offset 0x1000 (RVA 0x2000)
  IMAGE_IMPORT_DESCRIPTOR *imp_desc =
      reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR *>(fake_pe.data() + 0x1000);
  imp_desc->Name = 0x2100;               // RVA of module name
  imp_desc->OriginalFirstThunk = 0x2200; // RVA of ILT
  imp_desc->FirstThunk = 0x2300;         // RVA of IAT

  // Module name at offset 0x1100 (RVA 0x2100)
  memcpy(fake_pe.data() + 0x1100, "kernel32.dll", 13);

  // ILT at offset 0x1200 (RVA 0x2200)
  uint64_t *ilt = reinterpret_cast<uint64_t *>(fake_pe.data() + 0x1200);
  ilt[0] = 0x2400; // RVA of hint/name
  ilt[1] = 0;      // Terminate

  // Hint/name at offset 0x1400 (RVA 0x2400)
  uint8_t *name_data = fake_pe.data() + 0x1400;
  *reinterpret_cast<uint16_t *>(name_data) = 1; // Hint
  memcpy(name_data + 2, "ExitProcess", 12);

  PeParser parser(fake_pe);
  assert(parser.parse());
  assert(parser.get_imports().size() == 1);
  assert(parser.get_imports()[0].name == "kernel32.dll");
  assert(parser.get_imports()[0].entries.size() == 1);
  assert(parser.get_imports()[0].entries[0].function_name == "ExitProcess");

  std::cout << "test_pe_parser_imports passed!" << std::endl;
}

int main() {
  try {
    test_pe_parser_basic();
    test_pe_parser_imports();
  } catch (const std::exception &e) {
    std::cerr << "Test failed: " << e.what() << std::endl;
    return 1;
  }
  return 0;
}
