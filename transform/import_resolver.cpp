#include "import_resolver.hpp"

namespace exe2mem {
namespace transform {

ImportResolver::ImportResolver(const core::PeParser &parser)
    : m_parser(parser) {}

bool ImportResolver::resolve(MemoryImage &image,
                             ImportResolutionStrategy strategy) const {
  // For now, only IAT_PATCHING is conceptually implemented in this stage.
  // In a real reflective loader, IAT patching happens AT RUNTIME.
  // However, some pre-resolution or metadata generation could happen here.

  if (strategy == ImportResolutionStrategy::IAT_PATCHING) {
    // Prepare metadata for the runtime loader to patch the IAT.
  }

  return true;
}

} // namespace transform
} // namespace exe2mem
