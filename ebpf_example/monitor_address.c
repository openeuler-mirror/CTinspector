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

	*vm_va = 0;
	monitor_address(MONITOR_T_EQUAL_VALUE, (uint64_t)vm_va, test_value, 0);
	wait_for_address_event();
	debug_print(*vm_va);

	return 0;
}