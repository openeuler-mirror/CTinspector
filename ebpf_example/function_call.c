#include <stdint.h>
#include <stddef.h>
#include <ebpf_vm_functions.h>

uint64_t test(uint64_t a, uint64_t b, uint64_t c, uint64_t d, uint64_t *e)
{
	uint64_t sum = a + b + c + d;
	uint64_t *p1 = e + 1;
	uint64_t *p2 = e + 2;
	return sum + *p1 + *p2;
}

uint64_t vm_main(void)
{
	uint64_t tmp[3] = {0};
	uint64_t sum = test(1, 2, 3, 4, tmp);
	debug_print(sum);
	
	return 0;
}