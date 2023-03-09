#include <stdint.h>
#include <stddef.h>
#include <ebpf_vm_functions.h>

uint64_t vm_main(uint64_t host_va, uint64_t size, uint64_t test_value)
{
	uint64_t *vm_va;
	
	vm_va = (uint64_t *)mmap(host_va, size);
	if (vm_va == INVALID_MMAP_ADDR) {
		return -1;
	}

	debug_print(*vm_va);
	*vm_va = test_value;
	debug_print(*vm_va);
	
	return 0;
}