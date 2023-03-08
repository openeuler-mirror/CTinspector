#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <stdatomic.h>
#include <ctype.h>
#include <pthread.h>
#include <getopt.h>

#include "mp_vm_test.h"

struct test_config {
	int test_value;
};

struct monitor_test_context {
	pthread_t thread;
	uint64_t test_mem;
	uint64_t test_value;
} test_ctx;

static void *thread_change_test_mem(void *unused)
{
	sleep(1);
	test_ctx.test_mem = test_ctx.test_value;
	return NULL;
}

static int parse_test_config(struct test_config *cfg, int argc, char **argv)
{
	static struct option long_options[] = {
		{.name = "test-value", .has_arg = 1, .val = 'v'},
		{}
	};
	
	while (1) {
		int c = getopt_long(argc, argv, "v:", long_options, NULL);
		if (c == -1)
			break;
		
		switch (c) {
		case 'v':
			cfg->test_value = strtoul(optarg, NULL, 0);
			break;
		}
	}
	
	return 0;
}

static void *monitor_addr_test_setup(struct ebpf_vm_executor *executor, struct ebpf_vm *vm, int argc, char **argv)
{
	struct test_config test_cfg = {0};
	
	if (parse_test_config(&test_cfg, argc, argv) != 0) {
		perror("failed to parse test config");
		return NULL;
	}
	
	test_ctx.test_value = test_cfg.test_value;
	
	vm->reg[1] = (uint64_t)&test_ctx.test_mem;
	vm->reg[2] = sizeof(test_ctx.test_mem);
	vm->reg[3] = test_ctx.test_value;

	pthread_create(&test_ctx.thread, NULL, thread_change_test_mem, NULL);
	return &test_ctx;
}

static void monitor_addr_test_teardown(void *ctx)
{
	return;
}

static struct vm_test_case monitor_addr_test = {
	.index = MP_VM_TEST_MONITOR_ADDR,
	.setup = monitor_addr_test_setup,
	.teardown = monitor_addr_test_teardown
};

static __attribute__((constructor)) void monitor_addr_register_test(void)
{
	register_test_case(&monitor_addr_test);
}