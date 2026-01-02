#include "memory_layout_builder.hpp"
#include <cstring>

namespace exe2mem {
namespace transform {

MemoryLayoutBuilder::MemoryLayoutBuilder(const core::PeParser &parser)
    : m_parser(parser) {}

MemoryImage MemoryLayoutBuilder::build() const {
  MemoryImage image;
  image.is_x64 = m_parser.is_x64();
  image.image_base = m_parser.get_image_base();
  image.size_of_image = m_parser.get_size_of_image();
  image.entry_point_rva = m_parser.get_entry_point_rva();

  // Allocate image buffer
  image.buffer.resize(image.size_of_image, 0);

  // Copy headers
  uint32_t size_of_headers = m_parser.get_size_of_headers();
  const auto &raw_data = m_parser.get_raw_data();
  if (size_of_headers > 0 && size_of_headers <= raw_data.size()) {
    std::memcpy(image.buffer.data(), raw_data.data(), size_of_headers);
  }

  // Copy sections
  uint16_t num_sections = m_parser.get_number_of_sections();
  for (uint16_t i = 0; i < num_sections; ++i) {
    auto section = m_parser.get_section_header(i);
    if (section && section->SizeOfRawData > 0) {
      uint32_t dest_rva = section->VirtualAddress;
      uint32_t src_offset = section->PointerToRawData;
      uint32_t copy_size = section->SizeOfRawData;

      if (dest_rva + copy_size <= image.size_of_image &&
          src_offset + copy_size <= raw_data.size()) {
        std::memcpy(image.buffer.data() + dest_rva,
                    raw_data.data() + src_offset, copy_size);
      }
    }
  }

  return image;
}

} // namespace transform
} // namespace exe2mem
