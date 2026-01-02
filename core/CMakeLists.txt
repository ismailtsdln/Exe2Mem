# Core library
add_library(exe2mem_core STATIC
    pe_parser/pe_parser.cpp
    pe_validator/pe_validator.cpp
)

target_include_directories(exe2mem_core PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/pe_parser
    ${CMAKE_CURRENT_SOURCE_DIR}/pe_validator
)
