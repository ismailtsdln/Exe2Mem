add_executable(exe2mem_cli
    exe2mem_cli.cpp
)

target_link_libraries(exe2mem_cli PRIVATE
    exe2mem_core
    exe2mem_transform
    exe2mem_loader
)
