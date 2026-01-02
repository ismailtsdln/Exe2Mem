#pragma once

#include "memory_layout_builder.hpp"

namespace exe2mem {
namespace transform {

class EntryPointRewriter {
public:
  bool rewrite(MemoryImage &image, uint32_t new_entry_rva) const;
};

} // namespace transform
} // namespace exe2mem
