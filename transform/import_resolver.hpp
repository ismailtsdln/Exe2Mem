#pragma once

#include "core/pe_parser/pe_parser.hpp"
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

class ImportResolver {
public:
  explicit ImportResolver(const core::PeParser &parser);

  bool resolve(MemoryImage &image, ImportResolutionStrategy strategy) const;

private:
  const core::PeParser &m_parser;
};

} // namespace transform
} // namespace exe2mem
