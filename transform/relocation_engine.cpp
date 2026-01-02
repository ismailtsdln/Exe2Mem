#include "relocation_engine.hpp"
#include <cstring>

namespace exe2mem {
namespace transform {

RelocationEngine::RelocationEngine(const core::PeParser &parser)
    : m_parser(parser) {}

bool RelocationEngine::apply(MemoryImage &image, uint64_t new_base) const {
  if (new_base == image.image_base)
    return true;

  int64_t delta = static_cast<int64_t>(new_base - image.image_base);
  const auto &relocs = m_parser.get_relocations();

  for (const auto &block : relocs) {
    for (const auto &entry : block.entries) {
      uint32_t patch_offset = entry.rva;

      // Check if within buffer
      if (patch_offset >= image.buffer.size())
        continue;

      uint8_t *patch_ptr = image.buffer.data() + patch_offset;

      switch (entry.type) {
      case 10: // IMAGE_REL_BASED_DIR64
        if (patch_offset + 8 <= image.buffer.size()) {
          *reinterpret_cast<uint64_t *>(patch_ptr) += delta;
        }
        break;
      case 3: // IMAGE_REL_BASED_HIGHLOW
        if (patch_offset + 4 <= image.buffer.size()) {
          *reinterpret_cast<uint32_t *>(patch_ptr) +=
              static_cast<uint32_t>(delta);
        }
        break;
      case 2: // IMAGE_REL_BASED_HIGH
        if (patch_offset + 2 <= image.buffer.size()) {
          uint16_t val = *reinterpret_cast<uint16_t *>(patch_ptr);
          val += static_cast<uint16_t>(delta >> 16);
          *reinterpret_cast<uint16_t *>(patch_ptr) = val;
        }
        break;
      case 1: // IMAGE_REL_BASED_LOW
        if (patch_offset + 2 <= image.buffer.size()) {
          uint16_t val = *reinterpret_cast<uint16_t *>(patch_ptr);
          val += static_cast<uint16_t>(delta & 0xFFFF);
          *reinterpret_cast<uint16_t *>(patch_ptr) = val;
        }
        break;
      default:
        // Skip unknown or absolute (0)
        break;
      }
    }
  }

  image.image_base = new_base;
  return true;
}

} // namespace transform
} // namespace exe2mem
