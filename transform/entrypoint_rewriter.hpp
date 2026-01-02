#pragma once

#include "memory_layout_builder.hpp"

namespace exe2mem {
namespace transform {

class EntryPointRewriter {
public:
  static bool rewrite(MemoryImage &image, uint32_t new_entry_rva);
};

} // namespace transform
} // namespace exe2mem
