#pragma once

#include "memory_layout_builder.hpp"
#include <cstdint>
#include <vector>

namespace exe2mem {
namespace transform {

class ExecutionBlobGenerator {
public:
  std::vector<uint8_t> generate(const MemoryImage &image,
                                const std::vector<uint8_t> &metadata) const;
};

} // namespace transform
} // namespace exe2mem
