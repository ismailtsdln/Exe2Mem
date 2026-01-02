#include "syscall_abstraction.hpp"

namespace exe2mem {
namespace loader {

// Placeholder for syscall logic.
// In a real implementation, this would involve assembly to transition to kernel
// mode.
uint32_t SyscallAbstraction::call(uint32_t syscall_number, ...) { return 0; }

} // namespace loader
} // namespace exe2mem
