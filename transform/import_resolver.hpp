#pragma once

#include "../core/pe_parser/pe_parser.hpp"
#include "memory_layout_builder.hpp"
#include <map>
#include <string>

namespace exe2mem {
namespace transform {

enum class ImportResolutionStrategy {
  IAT_PATCHING,
  RUNTIME_PROXY,
  SYSCALL_ADAPTATION
};

struct ImportMetadata {
  uint32_t module_name_rva;
  uint32_t first_thunk_rva;
  bool is_ordinal;
  uint16_t ordinal;
  uint32_t name_rva;
};

class ImportResolver {
public:
  explicit ImportResolver(const core::PeParser &parser);

  bool resolve(MemoryImage &image, ImportResolutionStrategy strategy) const;

  struct SerializedData {
    std::vector<uint8_t> buffer;
  };

  SerializedData serialize_imports() const;

private:
  const core::PeParser &m_parser;
};

} // namespace transform
} // namespace exe2mem
