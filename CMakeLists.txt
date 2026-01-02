cmake_minimum_required(VERSION 3.20)
project(Exe2Mem VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Strict warnings
if(MSVC)
    add_compile_options(/W4 /WX /permissive-)
else()
    add_compile_options(-Wall -Wextra -Wpedantic -Werror)
endif()

# Directories
include_directories(${CMAKE_CURRENT_SOURCE_DIR})

# Modules
add_subdirectory(core)
add_subdirectory(transform)
add_subdirectory(loader)
add_subdirectory(cli)

# Tests
enable_testing()
add_subdirectory(tests)
