#pragma once

#include "../core/pe_parser/pe_parser.hpp"
#include <cstdint>
#include <vector>

namespace exe2mem {
namespace transform {

struct MemoryImage {
  std::vector<uint8_t> buffer;
  uint64_t image_base;
  uint32_t size_of_image;
  uint32_t entry_point_rva;
  bool is_x64;
};

class MemoryLayoutBuilder {
public:
  explicit MemoryLayoutBuilder(const core::PeParser &parser);

  MemoryImage build() const;

private:
  const core::PeParser &m_parser;
};

} // namespace transform
} // namespace exe2mem
