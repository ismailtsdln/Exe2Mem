# 🚀 Exe2Mem

Modern binary transformation framework that converts Windows PE (EXE / DLL) files into memory-native executable blobs.

## 🎯 Overview

Exe2Mem transforms Portable Executable files into minimal, self-contained, memory-executable units with maximum compatibility and control. It eliminates the need for disk-backed execution by providing a modular, runtime-generated loader logic.

## 🏗️ Architecture

- **Core**: PE parser, validator, and analysis tools.
- **Transform**: Multi-stage transformation pipeline.
- **Loader**: Runtime stubs and API resolution logic.
- **CLI**: Command-line interface for ease of use.

## ⚙️ Requirements

- C++23 compatible compiler (MSVC, Clang-CL)
- CMake 3.20+
- Windows environments (x86 / x64)

## 🚀 Getting Started

```bash
mkdir build
cd build
cmake ..
cmake --build .
```

## ⚖️ License

This project is for research and educational purposes.
