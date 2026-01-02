#include "import_resolver.hpp"
#include <cstring>

namespace exe2mem {
namespace transform {

ImportResolver::ImportResolver(const core::PeParser &parser)
    : m_parser(parser) {}

bool ImportResolver::resolve(MemoryImage &image,
                             ImportResolutionStrategy strategy) const {
  // metadata is already parsed by PeParser, we just need to serialize it.
  (void)image;
  (void)strategy;
  return true;
}

ImportResolver::SerializedData ImportResolver::serialize_imports() const {
  SerializedData data;
  const auto &imports = m_parser.get_imports();

  // Simple serialization: [count][module_name_len][module_name][thunk_count...
  // But let's keep it simpler for the blob: just RVAs of descriptors if
  // possible, or a custom table.

  uint32_t mod_count = static_cast<uint32_t>(imports.size());
  data.buffer.resize(sizeof(uint32_t));
  std::memcpy(data.buffer.data(), &mod_count, sizeof(uint32_t));

  for (const auto &mod : imports) {
    // Module name RVA (we could extract it from PeParser or just use the name)
    // For runtime, we need the actual string or RVA to it.
    // PeParser has the imports with names already.

    uint32_t name_len = static_cast<uint32_t>(mod.name.size());
    size_t offset = data.buffer.size();
    data.buffer.resize(offset + sizeof(uint32_t) + name_len + 1);
    std::memcpy(data.buffer.data() + offset, &name_len, sizeof(uint32_t));
    std::memcpy(data.buffer.data() + offset + sizeof(uint32_t),
                mod.name.c_str(), name_len + 1);

    uint32_t entry_count = static_cast<uint32_t>(mod.entries.size());
    offset = data.buffer.size();
    data.buffer.resize(offset + sizeof(uint32_t));
    std::memcpy(data.buffer.data() + offset, &entry_count, sizeof(uint32_t));

    for (const auto &entry : mod.entries) {
      // We need: Thunk RVA to patch, and Function Name or Ordinal
      uint32_t thunk_rva = entry.thunk_rva;
      uint32_t func_name_len =
          static_cast<uint32_t>(entry.function_name.size());

      offset = data.buffer.size();
      data.buffer.resize(offset + sizeof(uint32_t) * 2 + func_name_len + 1);
      std::memcpy(data.buffer.data() + offset, &thunk_rva, sizeof(uint32_t));
      std::memcpy(data.buffer.data() + offset + sizeof(uint32_t),
                  &func_name_len, sizeof(uint32_t));
      std::memcpy(data.buffer.data() + offset + sizeof(uint32_t) * 2,
                  entry.function_name.c_str(), func_name_len + 1);
    }
  }

  return data;
}

} // namespace transform
} // namespace exe2mem
