#include "execution_blob_generator.hpp"

namespace exe2mem {
namespace transform {

std::vector<uint8_t>
ExecutionBlobGenerator::generate(const MemoryImage &image) const {
  std::vector<uint8_t> blob;

  // For now, the blob is just the memory image.
  // Future expansion: prepend a shellcode stub that performs runtime loading.

  blob = image.buffer;

  return blob;
}

} // namespace transform
} // namespace exe2mem
