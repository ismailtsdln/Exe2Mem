#include "runtime_stub.hpp"
#include "../api_resolver/api_resolver.hpp"
#include <cstring>
#include <iostream>

#ifdef _WIN32
#include <windows.h>
#endif

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

  // 1. Resolve Imports & Patch IAT
  size_t meta_offset = 0;
  uint32_t mod_count =
      *reinterpret_cast<const uint32_t *>(meta_ptr + meta_offset);
  meta_offset += sizeof(uint32_t);

  for (uint32_t i = 0; i < mod_count; ++i) {
    uint32_t name_len =
        *reinterpret_cast<const uint32_t *>(meta_ptr + meta_offset);
    meta_offset += sizeof(uint32_t);
    std::string mod_name_str(
        reinterpret_cast<const char *>(meta_ptr + meta_offset), name_len);
    meta_offset += name_len + 1;

#ifdef _WIN32
    std::wstring w_mod_name(mod_name_str.begin(), mod_name_str.end());
    uint64_t mod_handle = ApiResolver::get_module_handle(w_mod_name);
    if (!mod_handle) {
      // In a real loader, try LoadLibrary
      mod_handle =
          reinterpret_cast<uint64_t>(::LoadLibraryA(mod_name_str.c_str()));
    }
#else
    uint64_t mod_handle = 0; // Conceptual handle
#endif

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
      std::string func_name(
          reinterpret_cast<const char *>(meta_ptr + meta_offset),
          func_name_len);
      meta_offset += func_name_len + 1;

      if (mod_handle) {
        uint64_t addr = ApiResolver::get_proc_address(mod_handle, func_name);
        if (addr && (thunk_rva + (is_x64 ? 8 : 4) <= image_size)) {
          // We need to const_cast because image_ptr is part of the blob
          uint8_t *patch_at = const_cast<uint8_t *>(image_ptr + thunk_rva);
          if (is_x64) {
            *reinterpret_cast<uint64_t *>(patch_at) = addr;
          } else {
            *reinterpret_cast<uint32_t *>(patch_at) =
                static_cast<uint32_t>(addr);
          }
        }
      }
    }
  }

  // 2. Execute Entry Point
  std::cout << "[*] RuntimeStub: IAT patching complete. Jumping to RVA: 0x"
            << std::hex << entry_rva << std::dec << std::endl;

  // In a real scenario, we would transfer control here using EntryDispatcher
  // EntryDispatcher::dispatch(image_ptr + entry_rva);

  return true;
}

} // namespace loader
} // namespace exe2mem
