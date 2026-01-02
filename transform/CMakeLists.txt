# Transformation library
add_library(exe2mem_transform STATIC
    memory_layout_builder.cpp
    relocation_engine.cpp
    import_resolver.cpp
    entrypoint_rewriter.cpp
    execution_blob_generator.cpp
)

target_link_libraries(exe2mem_transform PUBLIC
    exe2mem_core
)

target_include_directories(exe2mem_transform PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)
