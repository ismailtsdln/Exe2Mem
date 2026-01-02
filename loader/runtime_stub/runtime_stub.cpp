#include "runtime_stub.hpp"
#include "../api_resolver/api_resolver.hpp"
#include <cstring>
#include <iostream>

namespace exe2mem {
namespace loader {

bool RuntimeStub::execute(const std::vector<uint8_t> &blob) {
  if (blob.size() < sizeof(uint32_t) * 3)
    return false;

  size_t offset = 0;
  uint32_t meta_size =
      *reinterpret_cast<const uint32_t *>(blob.data() + offset);
  offset += sizeof(uint32_t);
  const uint8_t *meta_ptr = blob.data() + offset;
  offset += meta_size;

  uint32_t image_size =
      *reinterpret_cast<const uint32_t *>(blob.data() + offset);
  offset += sizeof(uint32_t);
  const uint8_t *image_ptr = blob.data() + offset;
  offset += image_size;

  uint32_t entry_rva =
      *reinterpret_cast<const uint32_t *>(blob.data() + offset);
  offset += sizeof(uint32_t);
  uint8_t is_x64 = blob.data()[offset];

  // 1. Resolve Imports
  size_t meta_offset = 0;
  uint32_t mod_count =
      *reinterpret_cast<const uint32_t *>(meta_ptr + meta_offset);
  meta_offset += sizeof(uint32_t);

  for (uint32_t i = 0; i < mod_count; ++i) {
    uint32_t name_len =
        *reinterpret_cast<const uint32_t *>(meta_ptr + meta_offset);
    meta_offset += sizeof(uint32_t);
    const char *mod_name =
        reinterpret_cast<const char *>(meta_ptr + meta_offset);
    meta_offset += name_len + 1;

    // In a real loader, we'd use GetModuleHandle/LoadLibrary
    // For now, we use our placeholder ApiResolver (which calls WinAPI)
    // Note: Std-compilers on Mac won't have WinAPI, so this is
    // conceptual/Windows-target code.
    (void)mod_name;

    uint32_t entry_count =
        *reinterpret_cast<const uint32_t *>(meta_ptr + meta_offset);
    meta_offset += sizeof(uint32_t);
    for (uint32_t j = 0; j < entry_count; ++j) {
      uint32_t thunk_rva =
          *reinterpret_cast<const uint32_t *>(meta_ptr + meta_offset);
      meta_offset += sizeof(uint32_t);
      uint32_t func_name_len =
          *reinterpret_cast<const uint32_t *>(meta_ptr + meta_offset);
      meta_offset += sizeof(uint32_t);
      const char *func_name =
          reinterpret_cast<const char *>(meta_ptr + meta_offset);
      meta_offset += func_name_len + 1;

      // Patch IAT at image_ptr + thunk_rva
      // uint64_t addr = ApiResolver::get_proc_address(mod_handle, func_name);
      // std::memcpy(const_cast<uint8_t*>(image_ptr + thunk_rva), &addr, is_x64
      // ? 8 : 4);
      (void)thunk_rva;
      (void)func_name;
      (void)is_x64;
      (void)image_ptr;
    }
  }

  // 2. Execute Entry Point (Placeholder)
  std::cout << "[*] RuntimeStub: Metadata parsed. Ready to jump to RVA: 0x"
            << std::hex << entry_rva << std::dec << std::endl;

  return true;
}

} // namespace loader
} // namespace exe2mem
