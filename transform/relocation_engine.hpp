#pragma once

#include "../core/pe_parser/pe_parser.hpp"
#include "memory_layout_builder.hpp"

namespace exe2mem {
namespace transform {

class RelocationEngine {
public:
  explicit RelocationEngine(const core::PeParser &parser);

  bool apply(MemoryImage &image, uint64_t new_base) const;

private:
  const core::PeParser &m_parser;
};

} // namespace transform
} // namespace exe2mem
