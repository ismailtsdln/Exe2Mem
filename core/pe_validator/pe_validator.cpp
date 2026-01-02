#include "pe_validator.hpp"

namespace exe2mem {
namespace core {

PeValidator::PeValidator(const PeParser &parser) : m_parser(parser) {}

bool PeValidator::validate() const {
  m_errors.clear();

  auto file_header = m_parser.get_file_header();
  if (!file_header) {
    m_errors.push_back("Missing File Header");
    return false;
  }

  if (file_header->NumberOfSections == 0) {
    m_errors.push_back("PE has no sections");
  }

  return m_errors.empty();
}

const std::vector<std::string> &PeValidator::get_errors() const {
  return m_errors;
}

} // namespace core
} // namespace exe2mem
