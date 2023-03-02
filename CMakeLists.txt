#packet vm makefile

cmake_minimum_required(VERSION 3.12.1)
project(ebpf_vm)

add_compile_options(-g)
add_subdirectory (ebpf_vm_executor)
add_subdirectory (ebpf_vm_test)
