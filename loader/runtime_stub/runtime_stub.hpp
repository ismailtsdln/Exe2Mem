#pragma once

#include <cstdint>
#include <vector>

namespace exe2mem {
namespace loader {

class RuntimeStub {
public:
  static bool execute(const std::vector<uint8_t> &blob);
};

} // namespace loader
} // namespace exe2mem
