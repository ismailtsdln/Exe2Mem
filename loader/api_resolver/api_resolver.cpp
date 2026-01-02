#include "api_resolver.hpp"

#ifdef _WIN32
#include <windows.h>
#include <winternl.h>
#endif

namespace exe2mem {
namespace loader {

uint64_t ApiResolver::get_module_handle(const std::wstring_view &module_name) {
#ifdef _WIN32
  return reinterpret_cast<uint64_t>(::GetModuleHandleW(module_name.data()));
#else
  (void)module_name;
  return 0;
#endif
}

uint64_t ApiResolver::get_proc_address(uint64_t module_base,
                                       const std::string_view &func_name) {
#ifdef _WIN32
  return reinterpret_cast<uint64_t>(::GetProcAddress(
      reinterpret_cast<HMODULE>(module_base), func_name.data()));
#else
  (void)module_base;
  (void)func_name;
  return 0;
#endif
}

} // namespace loader
} // namespace exe2mem
