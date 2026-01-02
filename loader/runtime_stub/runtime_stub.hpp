#pragma once

#include <cstdint>
#include <vector>

namespace exe2mem {
namespace loader {

class RuntimeStub {
public:
  void execute(const std::vector<uint8_t> &image_buffer, uint64_t entry_rva);
};

} // namespace loader
} // namespace exe2mem
