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

  // Check for section overlaps and boundary issues
  for (uint16_t i = 0; i < file_header->NumberOfSections; ++i) {
    auto s1 = m_parser.get_section_header(i);
    if (!s1)
      continue;

    if (s1->PointerToRawData + s1->SizeOfRawData >
        m_parser.get_raw_data().size()) {
      m_errors.push_back("Section " + std::to_string(i) +
                         " data out of bounds");
    }

    for (uint16_t j = i + 1; j < file_header->NumberOfSections; ++j) {
      auto s2 = m_parser.get_section_header(j);
      if (!s2)
        continue;

      if (s1->VirtualAddress < s2->VirtualAddress + s2->Misc.VirtualSize &&
          s2->VirtualAddress < s1->VirtualAddress + s1->Misc.VirtualSize) {
        m_errors.push_back("Section overlap detected: " + std::to_string(i) +
                           " and " + std::to_string(j));
      }
    }
  }

  return m_errors.empty();
}

const std::vector<std::string> &PeValidator::get_errors() const {
  return m_errors;
}

} // namespace core
} // namespace exe2mem
