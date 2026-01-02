#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace exe2mem {
namespace core {

#pragma pack(push, 1)

struct IMAGE_DOS_HEADER {
  uint16_t e_magic;
  uint16_t e_cblp;
  uint16_t e_cp;
  uint16_t e_crlc;
  uint16_t e_cparhdr;
  uint16_t e_minalloc;
  uint16_t e_maxalloc;
  uint16_t e_ss;
  uint16_t e_sp;
  uint16_t e_csum;
  uint16_t e_ip;
  uint16_t e_cs;
  uint16_t e_lfarlc;
  uint16_t e_ovno;
  uint16_t e_res[4];
  uint16_t e_oemid;
  uint16_t e_oeminfo;
  uint16_t e_res2[10];
  int32_t e_lfanew;
};

struct IMAGE_FILE_HEADER {
  uint16_t Machine;
  uint16_t NumberOfSections;
  uint32_t TimeDateStamp;
  uint32_t PointerToSymbolTable;
  uint32_t NumberOfSymbols;
  uint16_t SizeOfOptionalHeader;
  uint16_t Characteristics;
};

struct IMAGE_DATA_DIRECTORY {
  uint32_t VirtualAddress;
  uint32_t Size;
};

struct IMAGE_OPTIONAL_HEADER64 {
  uint16_t Magic;
  uint8_t MajorLinkerVersion;
  uint8_t MinorLinkerVersion;
  uint32_t SizeOfCode;
  uint32_t SizeOfInitializedData;
  uint32_t SizeOfUninitializedData;
  uint32_t AddressOfEntryPoint;
  uint32_t BaseOfCode;
  uint64_t ImageBase;
  uint32_t SectionAlignment;
  uint32_t FileAlignment;
  uint16_t MajorOperatingSystemVersion;
  uint16_t MinorOperatingSystemVersion;
  uint16_t MajorImageVersion;
  uint16_t MinorImageVersion;
  uint16_t MajorSubsystemVersion;
  uint16_t MinorSubsystemVersion;
  uint32_t Win32VersionValue;
  uint32_t SizeOfImage;
  uint32_t SizeOfHeaders;
  uint32_t CheckSum;
  uint16_t Subsystem;
  uint16_t DllCharacteristics;
  uint64_t SizeOfStackReserve;
  uint64_t SizeOfStackCommit;
  uint64_t SizeOfHeapReserve;
  uint64_t SizeOfHeapCommit;
  uint32_t LoaderFlags;
  uint32_t NumberOfRvaAndSizes;
  IMAGE_DATA_DIRECTORY DataDirectory[16];
};

struct IMAGE_OPTIONAL_HEADER32 {
  uint16_t Magic;
  uint8_t MajorLinkerVersion;
  uint8_t MinorLinkerVersion;
  uint32_t SizeOfCode;
  uint32_t SizeOfInitializedData;
  uint32_t SizeOfUninitializedData;
  uint32_t AddressOfEntryPoint;
  uint32_t BaseOfCode;
  uint32_t BaseOfData;
  uint32_t ImageBase;
  uint32_t SectionAlignment;
  uint32_t FileAlignment;
  uint16_t MajorOperatingSystemVersion;
  uint16_t MinorOperatingSystemVersion;
  uint16_t MajorImageVersion;
  uint16_t MinorImageVersion;
  uint16_t MajorSubsystemVersion;
  uint16_t MinorSubsystemVersion;
  uint32_t Win32VersionValue;
  uint32_t SizeOfImage;
  uint32_t SizeOfHeaders;
  uint32_t CheckSum;
  uint16_t Subsystem;
  uint16_t DllCharacteristics;
  uint32_t SizeOfStackReserve;
  uint32_t SizeOfStackCommit;
  uint32_t SizeOfHeapReserve;
  uint32_t SizeOfHeapCommit;
  uint32_t LoaderFlags;
  uint32_t NumberOfRvaAndSizes;
  IMAGE_DATA_DIRECTORY DataDirectory[16];
};

struct IMAGE_NT_HEADERS64 {
  uint32_t Signature;
  IMAGE_FILE_HEADER FileHeader;
  IMAGE_OPTIONAL_HEADER64 OptionalHeader;
};

struct IMAGE_NT_HEADERS32 {
  uint32_t Signature;
  IMAGE_FILE_HEADER FileHeader;
  IMAGE_OPTIONAL_HEADER32 OptionalHeader;
};

struct IMAGE_SECTION_HEADER {
  uint8_t Name[8];
  union {
    uint32_t PhysicalAddress;
    uint32_t VirtualSize;
  } Misc;
  uint32_t VirtualAddress;
  uint32_t SizeOfRawData;
  uint32_t PointerToRawData;
  uint32_t PointerToRelocations;
  uint32_t PointerToLinenumbers;
  uint16_t NumberOfRelocations;
  uint16_t NumberOfLinenumbers;
  uint32_t Characteristics;
};

struct IMAGE_IMPORT_DESCRIPTOR {
  uint32_t OriginalFirstThunk;
  uint32_t TimeDateStamp;
  uint32_t ForwarderChain;
  uint32_t Name;
  uint32_t FirstThunk;
};

struct IMAGE_BASE_RELOCATION {
  uint32_t VirtualAddress;
  uint32_t SizeOfBlock;
};

struct ImportEntry {
  std::string module_name;
  std::string function_name;
  uint16_t hint;
  uint32_t thunk_rva;
};

struct ImportModule {
  std::string name;
  std::vector<ImportEntry> entries;
};

struct RelocationEntry {
  uint32_t rva;
  uint16_t type;
};

struct RelocationBlock {
  uint32_t page_rva;
  std::vector<RelocationEntry> entries;
};

#pragma pack(pop)

class PeParser {
public:
  explicit PeParser(std::vector<uint8_t> data);

  bool parse();
  bool is_x64() const;

  const IMAGE_DOS_HEADER *get_dos_header() const;
  const IMAGE_FILE_HEADER *get_file_header() const;
  const IMAGE_SECTION_HEADER *get_section_header(uint16_t index) const;
  const IMAGE_DATA_DIRECTORY *get_data_directory(uint16_t index) const;

  uint32_t get_rva_to_offset(uint32_t rva) const;
  const uint8_t *get_rva_ptr(uint32_t rva) const;

  const std::vector<ImportModule> &get_imports() const { return m_imports; }
  const std::vector<RelocationBlock> &get_relocations() const {
    return m_relocations;
  }

private:
  bool parse_imports();
  bool parse_relocations();

  std::vector<uint8_t> m_raw_data;
  const IMAGE_DOS_HEADER *m_dos_header = nullptr;
  const IMAGE_NT_HEADERS64 *m_nt_headers64 = nullptr;
  const IMAGE_NT_HEADERS32 *m_nt_headers32 = nullptr;
  std::vector<const IMAGE_SECTION_HEADER *> m_sections;
  std::vector<ImportModule> m_imports;
  std::vector<RelocationBlock> m_relocations;
  bool m_is_x64 = false;
};

} // namespace core
} // namespace exe2mem
```
