#packet vm makefile

add_executable(vm_test mp_vm_test.c test_monitor_address.c)

include_directories(${CMAKE_SOURCE_DIR}/ebpf_vm_executor)
target_link_libraries(vm_test LINK_PUBLIC ebpf_vm_executor)