#pragma once

#include <cstdint>
#include <string_view>

namespace exe2mem {
namespace loader {

class ApiResolver {
public:
  static uint64_t get_module_handle(const std::wstring_view &module_name);
  static uint64_t get_proc_address(uint64_t module_base,
                                   const std::string_view &func_name);

private:
  // Helper to find LDR_DATA_TABLE_ENTRY
};

} // namespace loader
} // namespace exe2mem
