#include "api_resolver.hpp"
#include <windows.h>
#include <winternl.h>

namespace exe2mem {
namespace loader {

// Note: These implementations are meant to be executed on Windows.
// On Mac, these will only serve as a reference or use mock data if needed for
// testing.

uint64_t ApiResolver::get_module_handle(const std::wstring_view &module_name) {
  // In a real memory-native execution, we would walk the PEB LDR list.
  // For now, let's use GetModuleHandleW if available.
#ifdef _WIN32
  return reinterpret_cast<uint64_t>(::GetModuleHandleW(module_name.data()));
#else
  return 0;
#endif
}

uint64_t ApiResolver::get_proc_address(uint64_t module_base,
                                       const std::string_view &func_name) {
#ifdef _WIN32
  return reinterpret_cast<uint64_t>(::GetProcAddress(
      reinterpret_cast<HMODULE>(module_base), func_name.data()));
#else
  return 0;
#endif
}

} // namespace loader
} // namespace exe2mem
