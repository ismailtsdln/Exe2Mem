# Loader library
add_library(exe2mem_loader STATIC
    runtime_stub/runtime_stub.cpp
    api_resolver/api_resolver.cpp
    syscall_abstraction/syscall_abstraction.cpp
    entry_dispatcher/entry_dispatcher.cpp
)

target_include_directories(exe2mem_loader PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)
