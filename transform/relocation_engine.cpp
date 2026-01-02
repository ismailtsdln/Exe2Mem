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
      if (entry.rva + (image.is_x64 ? 8 : 4) > image.buffer.size())
        continue;

      uint8_t *patch_ptr = image.buffer.data() + entry.rva;

      if (image.is_x64) {
        if (entry.type == 10) { // IMAGE_REL_BASED_DIR64
          *reinterpret_cast<uint64_t *>(patch_ptr) += delta;
        }
      } else {
        if (entry.type == 3) { // IMAGE_REL_BASED_HIGHLOW
          *reinterpret_cast<uint32_t *>(patch_ptr) +=
              static_cast<uint32_t>(delta);
        }
      }
    }
  }

  image.image_base = new_base;
  return true;
}

} // namespace transform
} // namespace exe2mem
