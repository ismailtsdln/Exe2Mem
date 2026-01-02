#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>
#include <vector>

#include "../core/pe_parser/pe_parser.hpp"
#include "../core/pe_validator/pe_validator.hpp"
#include "../transform/entrypoint_rewriter.hpp"
#include "../transform/execution_blob_generator.hpp"
#include "../transform/import_resolver.hpp"
#include "../transform/memory_layout_builder.hpp"
#include "../transform/relocation_engine.hpp"

using namespace exe2mem;

void print_usage() {
  std::cout << "Usage: exe2mem_cli <input_pe> <output_blob>" << std::endl;
}

int main(int argc, char *argv[]) {
  if (argc < 3) {
    print_usage();
    return 1;
  }

  std::string input_path_str = argv[1];
  std::string output_path_str = argv[2];

  if (!std::filesystem::exists(input_path_str)) {
    std::cerr << "Error: Input file does not exist: " << input_path_str
              << std::endl;
    return 1;
  }

  std::ifstream file(input_path_str, std::ios::binary);
  std::vector<uint8_t> buffer((std::istreambuf_iterator<char>(file)),
                              std::istreambuf_iterator<char>());
  file.close();

  core::PeParser parser(std::move(buffer));
  if (!parser.parse()) {
    std::cerr << "Error: Failed to parse PE file." << std::endl;
    return 1;
  }

  core::PeValidator validator(parser);
  if (!validator.validate()) {
    std::cerr << "Error: PE validation failed:" << std::endl;
    for (const auto &err : validator.get_errors()) {
      std::cerr << "  - " << err << std::endl;
    }
    return 1;
  }

  std::cout << "PE file parsed and validated successfully." << std::endl;
  std::cout << "Architecture: " << (parser.is_x64() ? "x64" : "x86")
            << std::endl;
  std::cout << "Sections: " << parser.get_number_of_sections() << std::endl;

  transform::MemoryLayoutBuilder builder(parser);
  auto image = builder.build();

  transform::RelocationEngine reloc_engine(parser);
  reloc_engine.apply(image, image.image_base); // Rebase to own base for now

  transform::ExecutionBlobGenerator generator;
  auto blob = generator.generate(image);

  std::ofstream out_file(output_path_str, std::ios::binary);
  out_file.write(reinterpret_cast<const char *>(blob.data()), blob.size());
  out_file.close();

  std::cout << "Transformation complete. Execution blob written to: "
            << output_path_str << std::endl;

  return 0;
}
