#packet vm makefile

add_library(ebpf_vm_executor SHARED
	ebpf_vm_elf.c
	ebpf_vm_functions.c
	ebpf_vm_simulator.c
	ebpf_vm_transport_rdma.c
)

target_link_libraries(ebpf_vm_executor -lpthread -lelf -libverbs)
