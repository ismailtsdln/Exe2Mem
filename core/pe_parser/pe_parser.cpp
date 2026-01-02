#include "pe_parser.hpp"
#include <cstring>
#include <stdexcept>

namespace exe2mem {
namespace core {

PeParser::PeParser(std::vector<uint8_t> data) : m_raw_data(std::move(data)) {}

bool PeParser::parse() {
  if (m_raw_data.size() < sizeof(IMAGE_DOS_HEADER))
    return false;

  m_dos_header = reinterpret_cast<const IMAGE_DOS_HEADER *>(m_raw_data.data());
  if (m_dos_header->e_magic != 0x5A4D)
    return false;

  if (m_raw_data.size() < static_cast<size_t>(m_dos_header->e_lfanew) +
                              sizeof(uint32_t) + sizeof(IMAGE_FILE_HEADER))
    return false;

  const uint8_t *nt_header_ptr = m_raw_data.data() + m_dos_header->e_lfanew;
  uint32_t signature = *reinterpret_cast<const uint32_t *>(nt_header_ptr);
  if (signature != 0x00004550)
    return false;

  const IMAGE_FILE_HEADER *file_header =
      reinterpret_cast<const IMAGE_FILE_HEADER *>(nt_header_ptr + 4);
  if (file_header->Machine == 0x8664) {
    m_is_x64 = true;
    m_nt_headers64 =
        reinterpret_cast<const IMAGE_NT_HEADERS64 *>(nt_header_ptr);
  } else if (file_header->Machine == 0x014C) {
    m_is_x64 = false;
    m_nt_headers32 =
        reinterpret_cast<const IMAGE_NT_HEADERS32 *>(nt_header_ptr);
  } else
    return false;

  const IMAGE_SECTION_HEADER *section_ptr = nullptr;
  if (m_is_x64) {
    section_ptr = reinterpret_cast<const IMAGE_SECTION_HEADER *>(
        reinterpret_cast<const uint8_t *>(&m_nt_headers64->OptionalHeader) +
        file_header->SizeOfOptionalHeader);
  } else {
    section_ptr = reinterpret_cast<const IMAGE_SECTION_HEADER *>(
        reinterpret_cast<const uint8_t *>(&m_nt_headers32->OptionalHeader) +
        file_header->SizeOfOptionalHeader);
  }

  if (!validate_ptr(section_ptr, sizeof(IMAGE_SECTION_HEADER) *
                                     file_header->NumberOfSections))
    return false;
  for (uint16_t i = 0; i < file_header->NumberOfSections; ++i) {
    m_sections.push_back(section_ptr + i);
  }

  if (!parse_imports())
    return false;
  if (!parse_relocations())
    return false;
  return parse_tls();
}

bool PeParser::validate_ptr(const void *ptr, size_t size) const {
  const uint8_t *p = reinterpret_cast<const uint8_t *>(ptr);
  return (p >= m_raw_data.data() &&
          (p + size) <= (m_raw_data.data() + m_raw_data.size()));
}

bool PeParser::is_x64() const { return m_is_x64; }
const IMAGE_DOS_HEADER *PeParser::get_dos_header() const {
  return m_dos_header;
}
const IMAGE_FILE_HEADER *PeParser::get_file_header() const {
  if (m_is_x64)
    return &m_nt_headers64->FileHeader;
  return &m_nt_headers32->FileHeader;
}
const IMAGE_SECTION_HEADER *PeParser::get_section_header(uint16_t index) const {
  if (index >= m_sections.size())
    return nullptr;
  return m_sections[index];
}
const IMAGE_DATA_DIRECTORY *PeParser::get_data_directory(uint16_t index) const {
  if (index >= 16)
    return nullptr;
  if (m_is_x64)
    return &m_nt_headers64->OptionalHeader.DataDirectory[index];
  return &m_nt_headers32->OptionalHeader.DataDirectory[index];
}

uint32_t PeParser::get_rva_to_offset(uint32_t rva) const {
  // Check if RVA is within headers
  uint32_t size_of_headers = get_size_of_headers();
  if (rva < size_of_headers) {
    return rva;
  }

  for (const auto *section : m_sections) {
    if (rva >= section->VirtualAddress &&
        rva < (section->VirtualAddress + section->Misc.VirtualSize)) {

      uint32_t offset_in_section = rva - section->VirtualAddress;
      if (offset_in_section >= section->SizeOfRawData)
        return 0; // Padding area

      return section->PointerToRawData + offset_in_section;
    }
  }
  return 0;
}

const uint8_t *PeParser::get_rva_ptr(uint32_t rva) const {
  uint32_t offset = get_rva_to_offset(rva);
  if (offset == 0 || offset >= m_raw_data.size())
    return nullptr;
  return m_raw_data.data() + offset;
}

uint64_t PeParser::get_image_base() const {
  if (m_is_x64)
    return m_nt_headers64->OptionalHeader.ImageBase;
  return m_nt_headers32->OptionalHeader.ImageBase;
}

uint32_t PeParser::get_size_of_image() const {
  if (m_is_x64)
    return m_nt_headers64->OptionalHeader.SizeOfImage;
  return m_nt_headers32->OptionalHeader.SizeOfImage;
}

uint32_t PeParser::get_entry_point_rva() const {
  if (m_is_x64)
    return m_nt_headers64->OptionalHeader.AddressOfEntryPoint;
  return m_nt_headers32->OptionalHeader.AddressOfEntryPoint;
}

uint32_t PeParser::get_size_of_headers() const {
  if (m_is_x64)
    return m_nt_headers64->OptionalHeader.SizeOfHeaders;
  return m_nt_headers32->OptionalHeader.SizeOfHeaders;
}

uint16_t PeParser::get_number_of_sections() const {
  return get_file_header()->NumberOfSections;
}

bool PeParser::parse_imports() {
  auto import_dir = get_data_directory(1);
  if (!import_dir || import_dir->VirtualAddress == 0)
    return true;
  auto desc = reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR *>(
      get_rva_ptr(import_dir->VirtualAddress));
  if (!desc)
    return false;
  while (desc->Name != 0) {
    ImportModule mod;
    const char *mod_name =
        reinterpret_cast<const char *>(get_rva_ptr(desc->Name));
    if (mod_name)
      mod.name = mod_name;
    uint32_t thunk_rva =
        desc->OriginalFirstThunk ? desc->OriginalFirstThunk : desc->FirstThunk;
    auto thunk_ptr = get_rva_ptr(thunk_rva);
    if (thunk_ptr) {
      if (m_is_x64) {
        auto thunk64 = reinterpret_cast<const uint64_t *>(thunk_ptr);
        while (*thunk64 != 0) {
          if (!(*thunk64 & 0x8000000000000000ULL)) {
            auto name_data = reinterpret_cast<const uint8_t *>(
                get_rva_ptr(static_cast<uint32_t>(*thunk64)));
            if (name_data) {
              ImportEntry entry;
              entry.hint = *reinterpret_cast<const uint16_t *>(name_data);
              entry.function_name =
                  reinterpret_cast<const char *>(name_data + 2);
              entry.module_name = mod.name;
              entry.thunk_rva =
                  thunk_rva + (uint32_t)((const uint8_t *)thunk64 -
                                         (const uint8_t *)thunk_ptr);
              mod.entries.push_back(entry);
            }
          }
          thunk64++;
        }
      } else {
        auto thunk32 = reinterpret_cast<const uint32_t *>(thunk_ptr);
        while (*thunk32 != 0) {
          if (!(*thunk32 & 0x80000000)) {
            auto name_data =
                reinterpret_cast<const uint8_t *>(get_rva_ptr(*thunk32));
            if (name_data) {
              ImportEntry entry;
              entry.hint = *reinterpret_cast<const uint16_t *>(name_data);
              entry.function_name =
                  reinterpret_cast<const char *>(name_data + 2);
              entry.module_name = mod.name;
              entry.thunk_rva =
                  thunk_rva + (uint32_t)((const uint8_t *)thunk32 -
                                         (const uint8_t *)thunk_ptr);
              mod.entries.push_back(entry);
            }
          }
          thunk32++;
        }
      }
    }
    m_imports.push_back(mod);
    desc++;
  }
  return true;
}

bool PeParser::parse_relocations() {
  auto reloc_dir = get_data_directory(5);
  if (!reloc_dir || reloc_dir->VirtualAddress == 0)
    return true;
  auto current_reloc_ptr = get_rva_ptr(reloc_dir->VirtualAddress);
  if (!current_reloc_ptr)
    return false;
  uint32_t processed_size = 0;
  while (processed_size < reloc_dir->Size) {
    auto base_reloc = reinterpret_cast<const IMAGE_BASE_RELOCATION *>(
        current_reloc_ptr + processed_size);
    if (base_reloc->SizeOfBlock == 0)
      break;
    RelocationBlock block;
    block.page_rva = base_reloc->VirtualAddress;
    uint32_t entry_count =
        (base_reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) /
        sizeof(uint16_t);
    auto entries = reinterpret_cast<const uint16_t *>(
        current_reloc_ptr + processed_size + sizeof(IMAGE_BASE_RELOCATION));
    for (uint32_t i = 0; i < entry_count; ++i) {
      uint16_t type = entries[i] >> 12;
      uint16_t offset = entries[i] & 0x0FFF;
      if (type != 0) {
        RelocationEntry entry;
        entry.rva = block.page_rva + offset;
        entry.type = type;
        block.entries.push_back(entry);
      }
    }
    m_relocations.push_back(block);
    processed_size += base_reloc->SizeOfBlock;
  }
  return true;
}

bool PeParser::parse_tls() {
  auto tls_dir = get_data_directory(9); // IMAGE_DIRECTORY_ENTRY_TLS
  if (!tls_dir || tls_dir->VirtualAddress == 0)
    return true;
  uint32_t callbacks_va = 0;
  if (m_is_x64) {
    auto tls64 = reinterpret_cast<const IMAGE_TLS_DIRECTORY64 *>(
        get_rva_ptr(tls_dir->VirtualAddress));
    if (tls64)
      callbacks_va = static_cast<uint32_t>(
          tls64->AddressOfCallBacks - m_nt_headers64->OptionalHeader.ImageBase);
  } else {
    auto tls32 = reinterpret_cast<const IMAGE_TLS_DIRECTORY32 *>(
        get_rva_ptr(tls_dir->VirtualAddress));
    if (tls32)
      callbacks_va = static_cast<uint32_t>(
          tls32->AddressOfCallBacks - m_nt_headers32->OptionalHeader.ImageBase);
  }
  if (callbacks_va != 0) {
    auto ptr = get_rva_ptr(callbacks_va);
    if (ptr) {
      if (m_is_x64) {
        auto cb64 = reinterpret_cast<const uint64_t *>(ptr);
        while (*cb64 != 0) {
          m_tls_callbacks.push_back(*cb64);
          cb64++;
        }
      } else {
        auto cb32 = reinterpret_cast<const uint32_t *>(ptr);
        while (*cb32 != 0) {
          m_tls_callbacks.push_back(*cb32);
          cb32++;
        }
      }
    }
  }
  return true;
}

} // namespace core
} // namespace exe2mem
