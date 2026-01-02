# Exe2Mem

Exe2Mem is a high-performance C++23 framework for transforming Windows Portable Executable (PE) files into memory-native executable blobs. It is designed for security research, red team operations, and deep analysis of PE internals.

## Features

- **Robust PE Parsing**: Detailed analysis of DOS, NT, and Optional headers for both x86 and x64 architectures.
- **Advanced Transformation**:
  - **Memory Layout Reconstruction**: Builds a functional image layout in memory.
  - **Relocation Engine**: Full support for base relocations (DIR64, HIGHLOW, etc.).
  - **Import Metadata Serialization**: Prepares import data for runtime resolution.
  - **Entry Point Redirection**: Modify the execution start point via CLI.
- **Runtime Loader Stub**:
  - **Metadata Parsing**: Processes the structured blob payload.
  - **IAT Patching**: Resolves and patches the Import Address Table at runtime.
  - **Modular Runtime**: Clean abstraction for API resolution and syscalls.
- **Professional CLI**: Intuitive interface for complex transformation tasks.

## Project Structure

```text
├── core/           # PE Analysis Engine (Parser, Validator)
├── transform/      # Transformation Pipeline (Layout, Reloc, Imports)
├── loader/         # Runtime Loader Components (Stub, Resolvers)
├── cli/            # Command-Line Interface
└── tests/          # Unit and End-to-End Tests
```

## Getting Started

### Prerequisites

- C++23 compatible compiler (MSVC, Clang 17+)
- CMake 3.20+

### Usage

```bash
./exe2mem_cli <input_pe> <output_blob> [--entry <rva>]
```

## Security & Ethics

This tool is for research and educational purposes ONLY. Never use it on systems without explicit permission.
