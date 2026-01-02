#include "execution_blob_generator.hpp"

namespace exe2mem {
namespace transform {

std::vector<uint8_t>
ExecutionBlobGenerator::generate(const MemoryImage &image,
                                 const std::vector<uint8_t> &metadata) const {
  std::vector<uint8_t> blob;

  // Layout:
  // [SizeOfMetadata(4)][Metadata][SizeOfImage(4)][Image][EntryPointRVA(4)][IsX64(1)]
  uint32_t meta_size = static_cast<uint32_t>(metadata.size());
  uint32_t image_size = static_cast<uint32_t>(image.buffer.size());
  uint32_t entry_rva = image.entry_point_rva;
  uint8_t is_x64 = image.is_x64 ? 1 : 0;

  blob.resize(sizeof(uint32_t) * 3 + metadata.size() + image.buffer.size() + 1);

  size_t offset = 0;
  std::memcpy(blob.data() + offset, &meta_size, sizeof(uint32_t));
  offset += sizeof(uint32_t);
  std::memcpy(blob.data() + offset, metadata.data(), metadata.size());
  offset += metadata.size();
  std::memcpy(blob.data() + offset, &image_size, sizeof(uint32_t));
  offset += sizeof(uint32_t);
  std::memcpy(blob.data() + offset, image.buffer.data(), image.buffer.size());
  offset += image.buffer.size();
  std::memcpy(blob.data() + offset, &entry_rva, sizeof(uint32_t));
  offset += sizeof(uint32_t);
  std::memcpy(blob.data() + offset, &is_x64, 1);

  return blob;
}

} // namespace transform
} // namespace exe2mem
