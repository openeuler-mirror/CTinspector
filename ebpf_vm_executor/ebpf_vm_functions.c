#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <stdatomic.h>

#define PKT_VM_EXECUTOR 1

#include "ebpf_vm_simulator.h"
#include "ebpf_vm_functions.h"

static void address_monitor_list_add(uint64_t type, uint64_t monitor_address, uint64_t value, uint64_t tag, struct ebpf_vm *vm)
{
	struct address_monitor_entry *new_entry = NULL;
	new_entry = calloc(1, sizeof(*new_entry));
	if (new_entry == NULL) {
		return;
	}
	
	new_entry->type = type;
	new_entry->address = monitor_address;
	new_entry->value = value;
	new_entry->tag = tag;
	ub_list_push_head(&new_entry->list, &vm->address_monitor_list);
}

static struct address_monitor_entry *address_monitor_list_find(struct ebpf_vm *vm, uint64_t monitor_address)
{
	struct address_monitor_entry *entry, *tmp = NULL;
	if (ub_list_is_empty(&vm->address_monitor_list)) {
		return NULL;
	}
	UB_LIST_FOR_EACH_SAFE(entry, tmp, list, &vm->address_monitor_list) {
		if (entry->address == monitor_address) {
			return entry;
		}
	}
	return NULL;
}

static uint64_t ebpf_func_empty(ARG_NOT_USED_5, struct ebpf_vm *vm)
{
	printf("Warning: function is not resolved\n");
	return 0;
}

static uint64_t ebpf_func_debug_print(uint64_t s, ARG_NOT_USED_4, struct ebpf_vm *vm)
{
	printf("vm debug: %ld\n", s);
	return 0;
}

static uint64_t ebpf_func_mmap(uint64_t va, uint64_t size, ARG_NOT_USED_3, struct ebpf_vm *vm)
{
	int idx = vm->sys_reg[EBPF_SYS_REG_PAGE_TABLE_IDX];
	
	for (uint64_t index = 1; index < BUCKET_ENTRIES; index++) {
		if (vm->page_table[idx].entries[index].size == 0) {
			vm->page_table[idx].entries[index].va = va;
			vm->page_table[idx].entries[index].size = size;
			return (index << INDEX_SHIFT);
		}
	}
	
	return PAGE_TABLE_ERROR;
}

static uint64_t ebpf_func_wait_for_address_event(ARG_NOT_USED_5, struct ebpf_vm *vm)
{
	struct address_monitor_entry *e = NULL;
	uint64_t *host_va = NULL;
	
	UB_LIST_FOR_EACH(e, list, &vm->address_monitor_list) {
		host_va = (uint64_t *)vm_mmu(e->address, vm);
		if (((e->type == MONITOR_T_BIGGER_THAN_VALUE) && (*host_va <= e->value)) ||
			 ((e->type == MONITOR_T_LESS_THAN_VALUE) && (*host_va >= e->value)) ||
			 ((e->type == MONITOR_T_EQUAL_VALUE) && (*host_va != e->value)) ||
			 ((e->type == MONITOR_T_NOT_EQUAL_VALUE) && (*host_va == e->value))) {
			continue;
		}

		update_vm_state(vm, VM_STATE_RUNNING);
		return e->tag;
	}
	
	update_vm_state(vm, VM_STATE_WAIT_FOR_ADDRESS);
	return 0;
}

static uint64_t ebpf_func_monitor_address(uint64_t type, uint64_t target_address, uint64_t value, uint64_t tag, ARG_NOT_USED_1, struct ebpf_vm *vm)
{
	struct address_monitor_entry *entry, *tmp = NULL;
	entry = address_monitor_list_find(vm, target_address);
	if (type == MONITOR_T_CLEAR) {
		if (target_address == 0x0) {
			UB_LIST_FOR_EACH_SAFE(entry, tmp, list, &vm->address_monitor_list) {
				ub_list_remove(&entry->list);
				free(entry);
			}
			return 0;
		}
		if (entry != NULL) {
			ub_list_remove(&entry->list);
			free(entry);
		}
	} else {
		if (target_address == 0x0) {
			return -1;
		}
		if (entry == NULL) {
			(void)address_monitor_list_add(type, target_address, value, tag, vm);
		} else {
			entry->type = type;
			entry->value = value;
			entry->tag = tag;
		}
	}
	
	return 0;
}

static uint64_t ebpf_func_migrate_to(uint64_t dst, ARG_NOT_USED_4, struct ebpf_vm *vm)
{
	struct ebpf_vm_executor *executor = vm->rd.executor;
	struct transport_message send_msg;
	struct ub_address *addr = NULL;
	int ret;
	
	send_msg.buf = vm;
	send_msg.buf_size = sizeof(struct ebpf_vm) + vm->code_size + vm->stack_size + vm->data_size;
	addr = (struct ub_address *)vm_mmu(dst, vm);
	
	ret = executor->transport->send(executor->transport_ctx, (struct node_url *)addr->url, &send_msg);
	if (ret != send_msg.buf_size) {
		printf("Failed to migrate vm.");
	}
	
	update_vm_state(vm, VM_STATE_EXIT);
}

static uint64_t ebpf_func_clone_to(uint64_t dst_list, uint64_t len, ARG_NOT_USED_3, struct ebpf_vm *vm)
{
	struct ebpf_vm_executor *executor = vm->rd.executor;
	struct transport_message send_msg;
	struct ub_address *target_list = NULL;
	
	send_msg.buf = vm;
	send_msg.buf_size = sizeof(struct ebpf_vm) + vm->code_size + vm->stack_size + vm->data_size;
	target_list = (struct ub_address *)vm_mmu(dst_list, vm);
	
	for (int idx = 0; idx < len; idx++) {
		struct node_url *dst;
		int ret;
		
		dst = (struct node_url *)target_list[idx].url;
		vm->reg[0] = idx;
		ret = executor->transport->send(executor->transport_ctx, dst, &send_msg);
		if (ret != send_msg.buf_size) {
			printf("Failed to migrate vm.");
		}
	}
	
	return len;
}

static uint64_t ebpf_func_switch_to_address_space(uint64_t asid, ARG_NOT_USED_4, struct ebpf_vm *vm)
{
	if (asid >= BUCKET_ENTRIES) {
		printf("Only 2 address space are supported.");
		return 0;
	}
	
	vm->sys_reg[EBPF_SYS_REG_PAGE_TABLE_IDX] = asid;
	return 0;
}

static uint64_t ebpf_func_memcpy(uint64_t dst, uint64_t src, uint64_t len, uint64_t completion_addr, uint64_t result, struct ebpf_vm *vm)
{
	/*TBD*/
	return 0;
}

struct ebpf_symbol ebpf_global_symbs[PKT_VM_MAX_SYMBS] = {
	{"bug", ebpf_func_empty},
	{"debug_print", ebpf_func_debug_print},
	{"mmap", ebpf_func_mmap},
	{"monitor_address", ebpf_func_monitor_address},
	{"wait_for_address_event", ebpf_func_wait_for_address_event},
	{"migrate_to", ebpf_func_migrate_to},
	{"clone_to", ebpf_func_clone_to},
	{"switch_to_address_space", ebpf_func_switch_to_address_space},
	{"memcpy", ebpf_func_memcpy},
	{NULL, NULL}
};