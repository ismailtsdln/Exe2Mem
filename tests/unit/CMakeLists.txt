add_executable(test_pe_parser
    test_pe_parser.cpp
)

target_link_libraries(test_pe_parser PRIVATE
    exe2mem_core
)

add_test(NAME test_pe_parser COMMAND test_pe_parser)
