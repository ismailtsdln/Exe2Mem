#pragma once

#include <cstdint>

namespace exe2mem {
namespace loader {

class SyscallAbstraction {
public:
  static uint32_t call(uint32_t syscall_number, ...);
};

} // namespace loader
} // namespace exe2mem
