#ifndef _EBPF_VM_FUNCTIONS_H_
#define _EBPF_VM_FUNCTIONS_H_

#define ARG_NOT_USED_6 uint64_t not_used1, uint64_t not_used2, uint64_t not_used3, uint64_t not_used4, uint64_t not_used5, uint64_t not_used6
#define ARG_NOT_USED_5 uint64_t not_used1, uint64_t not_used2, uint64_t not_used3, uint64_t not_used4, uint64_t not_used5
#define ARG_NOT_USED_4 uint64_t not_used1, uint64_t not_used2, uint64_t not_used3, uint64_t not_used4
#define ARG_NOT_USED_3 uint64_t not_used1, uint64_t not_used2, uint64_t not_used3
#define ARG_NOT_USED_2 uint64_t not_used1, uint64_t not_used2
#define ARG_NOT_USED_1 uint64_t not_used1

#define VM_URL_SIZE 24
#define INVALID_MMAP_ADDR ((void *)-1)

#define join_thread fork_join

enum {
	MONITOR_T_BIGGER_THAN_VALUE,
	MONITOR_T_LESS_THAN_VALUE,
	MONITOR_T_EQUAL_VALUE,
	MONITOR_T_NOT_EQUAL_VALUE,
	MONITOR_T_CLEAR
};

enum {
	EBPF_FUNC_debug_print = 1,
	EBPF_FUNC_mmap,
	EBPF_FUNC_monitor_address,
	EBPF_FUNC_wait_for_address_event,
	EBPF_FUNC_migrate_to,
	EBPF_FUNC_clone_to,
	EBPF_FUNC_switch_to_address_space,
	EBPF_FUNC_memcpy,
	EBPF_FUNC_fork_to,
	EBPF_FUNC_fork_return,
	EBPF_FUNC_fork_join
};

struct ub_address {
	uint64_t access_key;
	uint8_t url[VM_URL_SIZE];
};

struct remote_thread {
	struct ub_address target_node;
	uint64_t id;
	uint64_t result;
};

#ifndef PKT_VM_EXECUTOR

static uint64_t (*debug_print)(uint64_t s) = (void *)EBPF_FUNC_debug_print;
static uint64_t (*mmap)(uint64_t va, uint64_t size) = (void *)EBPF_FUNC_mmap;
static uint64_t (*monitor_address)(uint64_t type, uint64_t target_address, uint64_t value, uint64_t tag) = (void *)EBPF_FUNC_monitor_address;
static uint64_t (*wait_for_address_event)(void) = (void *)EBPF_FUNC_wait_for_address_event;
static uint64_t (*migrate_to)(struct ub_address *dst) = (void *)EBPF_FUNC_migrate_to;
static uint64_t (*clone_to)(struct ub_address *target_list, int len) = (void *)EBPF_FUNC_clone_to;
static uint64_t (*fork_to)(struct remote_thread *thread_list, int len) = (void *)EBPF_FUNC_fork_to;
static uint64_t (*fork_return)(uint64_t result) = (void *)EBPF_FUNC_fork_return;
static uint64_t (*fork_join)(struct remote_thread *thread_list, int len) = (void *)EBPF_FUNC_fork_join;
static uint64_t (*switch_to_address_space)(int asid) = (void *)EBPF_FUNC_switch_to_address_space;
static uint64_t (*memcpy)(struct ub_address *dst, struct ub_address *src, int len, void *completion_addr, int result) = (void *)EBPF_FUNC_memcpy;

#define start_remote_thread(THREAD_LIST, LEN) for(uint64_t result = fork_to(THREAD_LIST, LEN); \
													result < (LEN); \
													fork_return(result))

#endif /*PKT_VM_EXECUTOR*/
#endif /*_EBPF_VM_FUNCTIONS_H_*/