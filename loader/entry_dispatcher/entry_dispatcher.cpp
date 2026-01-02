#include "entry_dispatcher.hpp"

namespace exe2mem {
namespace loader {

void EntryDispatcher::dispatch(uint64_t entry_point) {
  auto entry = reinterpret_cast<void (*)()>(entry_point);
  entry();
}

} // namespace loader
} // namespace exe2mem
