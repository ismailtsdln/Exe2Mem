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
  std::cout << "Usage: exe2mem_cli <input_pe> <output_blob> [--entry <rva>]"
            << std::endl;
}

int main(int argc, char *argv[]) {
  if (argc < 3) {
    print_usage();
    return 1;
  }

  const std::string input_path_str = argv[1];
  const std::string output_path_str = argv[2];
  uint32_t custom_entry_rva = 0;
  bool has_custom_entry = false;

  for (int i = 3; i < argc; ++i) {
    if (std::string(argv[i]) == "--entry" && i + 1 < argc) {
      custom_entry_rva =
          static_cast<uint32_t>(std::stoul(argv[i + 1], nullptr, 0));
      has_custom_entry = true;
      i++;
    }
  }

  try {
    std::ifstream file(input_path_str, std::ios::binary);
    if (!file) {
      std::cerr << "Error: Could not open input file." << std::endl;
      return 1;
    }

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
      std::cerr << "Error: PE validation failed." << std::endl;
      return 1;
    }

    transform::MemoryLayoutBuilder builder(parser);
    auto image = builder.build();

    transform::RelocationEngine reloc_engine(parser);
    reloc_engine.apply(image, image.image_base);

    if (has_custom_entry) {
      if (!transform::EntryPointRewriter::rewrite(image, custom_entry_rva)) {
        std::cerr << "Warning: Failed to rewrite entry point. Using original."
                  << std::endl;
      } else {
        std::cout << "[*] Entry point rewritten to RVA: 0x" << std::hex
                  << custom_entry_rva << std::dec << std::endl;
      }
    }

    transform::ImportResolver import_resolver(parser);
    auto meta = import_resolver.serialize_imports();

    transform::ExecutionBlobGenerator generator;
    auto blob = generator.generate(image, meta.buffer);

    std::ofstream out_file(output_path_str, std::ios::binary);
    if (!out_file) {
      std::cerr << "Error: Could not open output file for writing."
                << std::endl;
      return 1;
    }

    out_file.write(reinterpret_cast<const char *>(blob.data()), blob.size());
    out_file.close();

    std::cout << "[+] Transformation complete. Execution blob written to: "
              << output_path_str << std::endl;

  } catch (const std::exception &e) {
    std::cerr << "Error: " << e.what() << std::endl;
    return 1;
  }

  return 0;
}
