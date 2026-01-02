#pragma once

#include <cstdint>

namespace exe2mem {
namespace loader {

class EntryDispatcher {
public:
  static bool dispatch(void *entry_point);
};

} // namespace loader
} // namespace exe2mem
