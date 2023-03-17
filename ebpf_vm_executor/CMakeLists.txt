#packet vm makefile

add_library(ebpf_vm_executor SHARED
	ebpf_vm_elf.c
	ebpf_vm_functions.c
	ebpf_vm_simulator.c
	ebpf_vm_transport_rdma.c
)

target_link_libraries(ebpf_vm_executor -lpthread -lelf -libverbs)


install(TARGETS  ebpf_vm_executor DESTINATION ${LIB_INSTALL_PREFIX})
install(FILES  ebpf_vm_functions.h DESTINATION ${INCLUDE_INSTALL_PREFIX})
install(FILES  ebpf_vm_simulator.h DESTINATION ${INCLUDE_INSTALL_PREFIX})
install(FILES  ebpf_vm_transport_rdma.h DESTINATION ${INCLUDE_INSTALL_PREFIX})
install(FILES  list.h DESTINATION ${INCLUDE_INSTALL_PREFIX})
install(FILES  ub_list.h DESTINATION ${INCLUDE_INSTALL_PREFIX})
