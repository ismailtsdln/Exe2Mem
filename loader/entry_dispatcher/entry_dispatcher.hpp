#pragma once

#include <cstdint>

namespace exe2mem {
namespace loader {

class EntryDispatcher {
public:
  static void dispatch(uint64_t entry_point);
};

} // namespace loader
} // namespace exe2mem
