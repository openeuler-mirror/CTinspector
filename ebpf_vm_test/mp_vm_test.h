#ifndef _MP_VM_TEST_H_
#define _MP_VM_TEST_H_

#include "ebpf_vm_simulator.h"

enum {
	MP_VM_TEST_GENERAL,
	MP_VM_TEST_MONITOR_ADDR,
	MP_VM_TEST_NUM
};

struct vm_test_case {
	int index;
	void *(*setup)(struct ebpf_vm_executor *executor, struct ebpf_vm *vm, int argc, char **argv);
	void (*teardown)(void *ctx);
};

int register_test_case(struct vm_test_case *test);

#endif