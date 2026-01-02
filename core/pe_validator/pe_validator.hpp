#pragma once

#include "../pe_parser/pe_parser.hpp"
#include <string>
#include <vector>

namespace exe2mem {
namespace core {

class PeValidator {
public:
  explicit PeValidator(const PeParser &parser);

  bool validate() const;
  const std::vector<std::string> &get_errors() const;

private:
  const PeParser &m_parser;
  mutable std::vector<std::string> m_errors;
};

} // namespace core
} // namespace exe2mem
