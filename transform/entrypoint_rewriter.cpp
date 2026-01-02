#include "entrypoint_rewriter.hpp"

namespace exe2mem {
namespace transform {

bool EntryPointRewriter::rewrite(MemoryImage &image, uint32_t new_entry_rva) {
  if (new_entry_rva >= image.size_of_image) {
    return false;
  }

  image.entry_point_rva = new_entry_rva;
  return true;
}

} // namespace transform
} // namespace exe2mem
