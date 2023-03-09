#include <stdint.h>
#include <stddef.h>
#include <ebpf_vm_functions.h>

void test_migrate(struct ub_address *a, struct ub_address *b, int cnt)
{
	uint64_t msg = 1000;
	int idx;
	
	for (idx = 0; idx < cnt; idx++) {
		debug_print(msg);
		msg += 1000;
		migrate_to(a);
		
		debug_print(msg);
		msg += 1000;
		migrate_to(b);
	}
}

uint64_t vm_main(void)
{
	struct ub_address a = {
		.access_key = 0,
		.url = {192, 168, 100, 10, 7, 89}
	};

	struct ub_address b = {
		.access_key = 0,
		.url = {192, 168, 100, 20, 7, 89}
	};

	/* Migrate to 1.1.8.78:1881 */
	test_migrate(&a, &b, 20);
	
	return 0;
}