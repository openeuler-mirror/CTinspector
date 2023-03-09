#include <stdint.h>
#include <stddef.h>
#include <ebpf_vm_functions.h>

uint64_t vm_main(void)
{
	struct ub_address dst[2] = {
		{
			.access_key = 0,
			.url = {1, 1, 8, 78, 7, 89}
		},
		{
			.access_key = 0,
			.url = {1, 1, 8, 78, 7, 90}
		},
	};
	int ret;
	
	debug_print(1000);
	ret = clone_to(dst, 2);
	if (ret == 2) {
		/* I am in the original node */
		debug_print(2000);
	} else if (ret == 0) {
		/* I am in the first destination node */
		debug_print(3000);
	} else {
		/* I am in the last destination node */
		debug_print(4000);
	}
	
	return 0;
}