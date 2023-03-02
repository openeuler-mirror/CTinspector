#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <stdatomic.h>
#include <ctype.h>
#include <pthread.h>
#include "ub_list.h"

#define PKT_VM_EXECUTOR 1

#include "ebpf_vm_simulator.h"
#include "ebpf_vm_transport.h"
#include "ebpf_vm_functions.h"

struct transport_ops *registered_transport[PKT_VM_TRANSPORT_TYPE_MAX];

static uint64_t to_little_endian(uint64_t *v, uint32_t width)
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	return *v;
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
	uint8_t *p = (uint8_t *)(v + 1);
	uint64_t result = 0;
	for (int idx = 0; idx < (width / 8); idx++) {
		result |= *(--p);
		result = result << 8;
	}
	return result;
#else
#error unsupported endianess
#endif
}

static uint64_t to_big_endian(uint64_t *v, uint32_t width)
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	uint8_t *p = (uint8_t *)v;
	uint64_t result = 0;
	for (int idx = 0; idx < (width / 8); idx++) {
		result |= *(p++);
		result = result << 8;
	}
	return result;
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
	return *v;
#else
#error unsupported endianess
#endif
}

uint64_t vm_mmu(uint64_t va, struct ebpf_vm *vm)
{
	struct vm_pte *e = NULL;
	uint64_t offset = va & ENTRY_MASK;
	int idx = vm->sys_reg[EBPF_SYS_REG_PAGE_TABLE_IDX];
	
	if ((va >> PACKET_VA_SHIFT) != 0) {
		return PAGE_TABLE_ERROR;
	}
	
	e = &vm->page_table[idx].entries[(va >> INDEX_SHIFT)];
	if ((e->va != 0x00) && (offset < e->size)) {
		return e->va + offset;
	}
	
	return PAGE_TABLE_ERROR;
}

void update_vm_state(struct ebpf_vm *vm, int state)
{
	vm->state.vm_state = state;
}

static void save_caller_register(struct ebpf_vm *vm)
{
	uint64_t *fp = (uint64_t *)vm_mmu(vm->reg[EBPF_REG_FP], vm);
	*fp++ = vm->reg[EBPF_REG_6];
	*fp++ = vm->reg[EBPF_REG_7];
	*fp++ = vm->reg[EBPF_REG_8];
	*fp++ = vm->reg[EBPF_REG_9];
	*fp++ = vm->sys_reg[EBPF_SYS_REG_LR];
}

static void restore_caller_register(struct ebpf_vm *vm)
{
	uint64_t *fp = (uint64_t *)vm_mmu(vm->reg[EBPF_REG_FP], vm);
	vm->reg[EBPF_REG_6] = *fp++;
	vm->reg[EBPF_REG_7] = *fp++;
	vm->reg[EBPF_REG_8] = *fp++;
	vm->reg[EBPF_REG_9] = *fp++;
	vm->sys_reg[EBPF_SYS_REG_LR] = *fp++;
}

uint64_t run_ebpf_vm(struct ebpf_vm *vm)
{
	struct ebpf_instruction *ins = ebpf_vm_code(vm) + vm->sys_reg[EBPF_SYS_REG_PC];
	
	while (1) {
		switch (ins->opcode) {
		case (EBPF_CLS_ALU64 | EBPF_ALU_OP_ADD | EBPF_SRC_IS_IMM): {
			vm->reg[ins->dst_reg] += (uint64_t)ins->immediate;
			break;
		}
		case (EBPF_CLS_ALU64 | EBPF_ALU_OP_ADD | EBPF_SRC_IS_REG): {
			vm->reg[ins->dst_reg] += vm->reg[ins->src_reg];
			break;
		}
		case (EBPF_CLS_ALU64 | EBPF_ALU_OP_SUB | EBPF_SRC_IS_IMM): {
			vm->reg[ins->dst_reg] -= (uint64_t)ins->immediate;
			break;
		}
		case (EBPF_CLS_ALU64 | EBPF_ALU_OP_SUB | EBPF_SRC_IS_REG): {
			vm->reg[ins->dst_reg] -= vm->reg[ins->src_reg];
			break;
		}
		case (EBPF_CLS_ALU64 | EBPF_ALU_OP_MUL | EBPF_SRC_IS_IMM): {
			vm->reg[ins->dst_reg] *= (uint64_t)ins->immediate;
			break;
		}
		case (EBPF_CLS_ALU64 | EBPF_ALU_OP_MUL | EBPF_SRC_IS_REG): {
			vm->reg[ins->dst_reg] *= vm->reg[ins->src_reg];
			break;
		}
		case (EBPF_CLS_ALU64 | EBPF_ALU_OP_DIV | EBPF_SRC_IS_IMM): {
			vm->reg[ins->dst_reg] /= (uint64_t)ins->immediate;
			break;
		}
		case (EBPF_CLS_ALU64 | EBPF_ALU_OP_DIV | EBPF_SRC_IS_REG): {
			vm->reg[ins->dst_reg] /= vm->reg[ins->src_reg];
			break;
		}
		case (EBPF_CLS_ALU64 | EBPF_ALU_OP_OR | EBPF_SRC_IS_IMM): {
			vm->reg[ins->dst_reg] |= (uint64_t)ins->immediate;
			break;
		}
		case (EBPF_CLS_ALU64 | EBPF_ALU_OP_OR | EBPF_SRC_IS_REG): {
			vm->reg[ins->dst_reg] |= vm->reg[ins->src_reg];
			break;
		}
		case (EBPF_CLS_ALU64 | EBPF_ALU_OP_AND | EBPF_SRC_IS_IMM): {
			vm->reg[ins->dst_reg] &= (uint64_t)ins->immediate;
			break;
		}
		case (EBPF_CLS_ALU64 | EBPF_ALU_OP_AND | EBPF_SRC_IS_REG): {
			vm->reg[ins->dst_reg] &= vm->reg[ins->src_reg];
			break;
		}
		case (EBPF_CLS_ALU64 | EBPF_ALU_OP_LSH | EBPF_SRC_IS_IMM): {
			vm->reg[ins->dst_reg] <<= (uint64_t)ins->immediate;
			break;
		}
		case (EBPF_CLS_ALU64 | EBPF_ALU_OP_LSH | EBPF_SRC_IS_REG): {
			vm->reg[ins->dst_reg] <<= vm->reg[ins->src_reg];
			break;
		}
		case (EBPF_CLS_ALU64 | EBPF_ALU_OP_RSH | EBPF_SRC_IS_IMM): {
			vm->reg[ins->dst_reg] >>= (uint64_t)ins->immediate;
			break;
		}
		case (EBPF_CLS_ALU64 | EBPF_ALU_OP_RSH | EBPF_SRC_IS_REG): {
			vm->reg[ins->dst_reg] >>= vm->reg[ins->src_reg];
			break;
		}
		case (EBPF_CLS_ALU64 | EBPF_ALU_OP_NEG): {
			vm->reg[ins->dst_reg] = (uint64_t)(-vm->reg[ins->dst_reg]);
			break;
		}
		case (EBPF_CLS_ALU64 | EBPF_ALU_OP_MOD | EBPF_SRC_IS_IMM): {
			vm->reg[ins->dst_reg] %= (uint64_t)ins->immediate;
			break;
		}
		case (EBPF_CLS_ALU64 | EBPF_ALU_OP_MOD | EBPF_SRC_IS_REG): {
			vm->reg[ins->dst_reg] %= vm->reg[ins->src_reg];
			break;
		}
		case (EBPF_CLS_ALU64 | EBPF_ALU_OP_XOR | EBPF_SRC_IS_IMM): {
			vm->reg[ins->dst_reg] ^= (uint64_t)ins->immediate;
			break;
		}
		case (EBPF_CLS_ALU64 | EBPF_ALU_OP_XOR | EBPF_SRC_IS_REG): {
			vm->reg[ins->dst_reg] ^= vm->reg[ins->src_reg];
			break;
		}
		case (EBPF_CLS_ALU64 | EBPF_ALU_OP_MOV | EBPF_SRC_IS_IMM): {
			vm->reg[ins->dst_reg] = (uint64_t)ins->immediate;
			break;
		}
		case (EBPF_CLS_ALU64 | EBPF_ALU_OP_MOV | EBPF_SRC_IS_REG): {
			vm->reg[ins->dst_reg] = vm->reg[ins->src_reg];
			break;
		}
		case (EBPF_CLS_ALU64 | EBPF_ALU_OP_ARSH | EBPF_SRC_IS_IMM): {
			vm->reg[ins->dst_reg] = (int64_t)vm->reg[ins->dst_reg] >> (int64_t)ins->immediate;
			break;
		}
		case (EBPF_CLS_ALU64 | EBPF_ALU_OP_ARSH | EBPF_SRC_IS_REG): {
			vm->reg[ins->dst_reg] = (int64_t)vm->reg[ins->dst_reg] >> (int64_t)vm->reg[ins->src_reg];
			break;
		}
		case (EBPF_CLS_JMP | EBPF_JMP_OP_JA): {
			ins += ins->offset;
			break;
		}
		case (EBPF_CLS_JMP | EBPF_JMP_OP_JEQ | EBPF_SRC_IS_IMM): {
			ins += ((uint64_t)vm->reg[ins->dst_reg] == (uint64_t)ins->immediate) ? ins->offset : 0;
			break;
		}
		case (EBPF_CLS_JMP | EBPF_JMP_OP_JEQ | EBPF_SRC_IS_REG): {
			ins += ((uint64_t)vm->reg[ins->dst_reg] == (uint64_t)vm->reg[ins->src_reg]) ? ins->offset : 0;
			break;
		}
		case (EBPF_CLS_JMP | EBPF_JMP_OP_JGT | EBPF_SRC_IS_IMM): {
			ins += ((uint64_t)vm->reg[ins->dst_reg] > (uint64_t)ins->immediate) ? ins->offset : 0;
			break;
		}
		case (EBPF_CLS_JMP | EBPF_JMP_OP_JGT | EBPF_SRC_IS_REG): {
			ins += ((uint64_t)vm->reg[ins->dst_reg] > (uint64_t)vm->reg[ins->src_reg]) ? ins->offset : 0;
			break;
		}
		case (EBPF_CLS_JMP | EBPF_JMP_OP_JGE | EBPF_SRC_IS_IMM): {
			ins += ((uint64_t)vm->reg[ins->dst_reg] >= (uint64_t)ins->immediate) ? ins->offset : 0;
			break;
		}
		case (EBPF_CLS_JMP | EBPF_JMP_OP_JGE | EBPF_SRC_IS_REG): {
			ins += ((uint64_t)vm->reg[ins->dst_reg] >= (uint64_t)vm->reg[ins->src_reg]) ? ins->offset : 0;
			break;
		}
		case (EBPF_CLS_JMP | EBPF_JMP_OP_JSET | EBPF_SRC_IS_IMM): {
			ins += ((uint64_t)vm->reg[ins->dst_reg] & (uint64_t)ins->immediate) ? ins->offset : 0;
			break;
		}
		case (EBPF_CLS_JMP | EBPF_JMP_OP_JSET | EBPF_SRC_IS_REG): {
			ins += ((uint64_t)vm->reg[ins->dst_reg] & (uint64_t)vm->reg[ins->src_reg]) ? ins->offset : 0;
			break;
		}
		case (EBPF_CLS_JMP | EBPF_JMP_OP_JNE | EBPF_SRC_IS_IMM): {
			ins += ((uint64_t)vm->reg[ins->dst_reg] != (uint64_t)ins->immediate) ? ins->offset : 0;
			break;
		}
		case (EBPF_CLS_JMP | EBPF_JMP_OP_JNE | EBPF_SRC_IS_REG): {
			ins += ((uint64_t)vm->reg[ins->dst_reg] != (uint64_t)vm->reg[ins->src_reg]) ? ins->offset : 0;
			break;
		}
		case (EBPF_CLS_JMP | EBPF_JMP_OP_JSGT | EBPF_SRC_IS_IMM): {
			ins += ((int64_t)vm->reg[ins->dst_reg] > (int64_t)ins->immediate) ? ins->offset : 0;
			break;
		}
		case (EBPF_CLS_JMP | EBPF_JMP_OP_JSGT | EBPF_SRC_IS_REG): {
			ins += ((int64_t)vm->reg[ins->dst_reg] > (int64_t)vm->reg[ins->src_reg]) ? ins->offset : 0;
			break;
		}
		case (EBPF_CLS_JMP | EBPF_JMP_OP_JSGE | EBPF_SRC_IS_IMM): {
			ins += ((int64_t)vm->reg[ins->dst_reg] >= (int64_t)ins->immediate) ? ins->offset : 0;
			break;
		}
		case (EBPF_CLS_JMP | EBPF_JMP_OP_JSGE | EBPF_SRC_IS_REG): {
			ins += ((int64_t)vm->reg[ins->dst_reg] >= (int64_t)vm->reg[ins->src_reg]) ? ins->offset : 0;
			break;
		}
		case (EBPF_CLS_JMP | EBPF_JMP_OP_CALL): {
			if (ins->src_reg == EBPF_PSEUDO_CALL) {
				save_caller_register(vm);
				vm->state.stack_depth++;
				vm->reg[EBPF_REG_FP] -= EBPF_VM_STACK_FRAME_SIZE;
				vm->sys_reg[EBPF_SYS_REG_LR] = ins - ebpf_vm_code(vm) + 1;
				vm->sys_reg[EBPF_SYS_REG_PC] = vm->sys_reg[EBPF_SYS_REG_LR] + ins->immediate;
				vm->reg[0] = run_ebpf_vm(vm);
				if (vm->state.vm_state != VM_STATE_RUNNING) {
					return 0;
				}
			} else if ((ins->immediate < PKT_VM_MAX_SYMBS) && (vm->rd.symbols[ins->immediate].func != NULL)) {
				vm->sys_reg[EBPF_SYS_REG_PC] = ins - ebpf_vm_code(vm);
				vm->reg[0] = vm->rd.symbols[ins->immediate].func(vm->reg[1], vm->reg[2], vm->reg[3], vm->reg[4], vm->reg[5], vm);
				if (vm->state.vm_state != VM_STATE_RUNNING) {
					return 0;
				}
			}
			break;
		}
		case (EBPF_CLS_JMP | EBPF_JMP_OP_EXIT): {
			if (vm->state.stack_depth != 0) {
				vm->sys_reg[EBPF_SYS_REG_PC] = vm->sys_reg[EBPF_SYS_REG_LR];
				vm->reg[EBPF_REG_FP] += EBPF_VM_STACK_FRAME_SIZE;
				vm->state.stack_depth--;
				restore_caller_register(vm);
			} else {
				update_vm_state(vm, VM_STATE_EXIT);
			}
			return vm->reg[0];
		}
		case (EBPF_CLS_JMP | EBPF_JMP_OP_JLT | EBPF_SRC_IS_IMM): {
			ins += ((uint64_t)vm->reg[ins->dst_reg] < (uint64_t)ins->immediate) ? ins->offset : 0;
			break;
		}
		case (EBPF_CLS_JMP | EBPF_JMP_OP_JLT | EBPF_SRC_IS_REG): {
			ins += ((uint64_t)vm->reg[ins->dst_reg] < (uint64_t)vm->reg[ins->src_reg]) ? ins->offset : 0;
			break;
		}
		case (EBPF_CLS_JMP | EBPF_JMP_OP_JLE | EBPF_SRC_IS_IMM): {
			ins += ((uint64_t)vm->reg[ins->dst_reg] <= (uint64_t)ins->immediate) ? ins->offset : 0;
			break;
		}
		case (EBPF_CLS_JMP | EBPF_JMP_OP_JLE | EBPF_SRC_IS_REG): {
			ins += ((uint64_t)vm->reg[ins->dst_reg] <= (uint64_t)vm->reg[ins->src_reg]) ? ins->offset : 0;
			break;
		}
		case (EBPF_CLS_JMP | EBPF_JMP_OP_JSLT | EBPF_SRC_IS_IMM): {
			ins += ((int64_t)vm->reg[ins->dst_reg] < (int64_t)ins->immediate) ? ins->offset : 0;
			break;
		}
		case (EBPF_CLS_JMP | EBPF_JMP_OP_JSLT | EBPF_SRC_IS_REG): {
			ins += ((int64_t)vm->reg[ins->dst_reg] < (int64_t)vm->reg[ins->src_reg]) ? ins->offset : 0;
			break;
		}
		case (EBPF_CLS_JMP | EBPF_JMP_OP_JSLE | EBPF_SRC_IS_IMM): {
			ins += ((int64_t)vm->reg[ins->dst_reg] <= (int64_t)ins->immediate) ? ins->offset : 0;
			break;
		}
		case (EBPF_CLS_JMP | EBPF_JMP_OP_JSLE | EBPF_SRC_IS_REG): {
			ins += ((int64_t)vm->reg[ins->dst_reg] <= (int64_t)vm->reg[ins->src_reg]) ? ins->offset : 0;
			break;
		}
		case (EBPF_CLS_LDX | EBPF_MEM | EBPF_B): {
			uint64_t host_va = vm_mmu(vm->reg[ins->src_reg] + ins->offset, vm);
			vm->reg[ins->dst_reg] = *((uint8_t *)host_va);
			break;
		}
		case (EBPF_CLS_LDX | EBPF_MEM | EBPF_H): {
			uint64_t host_va = vm_mmu(vm->reg[ins->src_reg] + ins->offset, vm);
			vm->reg[ins->dst_reg] = *((uint16_t *)host_va);
			break;
		}
		case (EBPF_CLS_LDX | EBPF_MEM | EBPF_W): {
			uint64_t host_va = vm_mmu(vm->reg[ins->src_reg] + ins->offset, vm);
			vm->reg[ins->dst_reg] = *((uint32_t *)host_va);
			break;
		}
		case (EBPF_CLS_LDX | EBPF_MEM | EBPF_DW): {
			uint64_t host_va = vm_mmu(vm->reg[ins->src_reg] + ins->offset, vm);
			vm->reg[ins->dst_reg] = *((uint64_t *)host_va);
			break;
		}
		case (EBPF_CLS_LD | EBPF_IMM | EBPF_DW): {
			vm->reg[ins->dst_reg] = (uint32_t)ins[0].immediate | ((uint64_t)ins[1].immediate << 32);
			ins++;
			break;
		}
		case (EBPF_CLS_STX | EBPF_MEM | EBPF_B): {
			uint64_t store_addr = vm_mmu(vm->reg[ins->dst_reg] + ins->offset, vm);
			*(uint8_t *)store_addr = (uint8_t)vm->reg[ins->src_reg];
			break;
		}
		case (EBPF_CLS_STX | EBPF_MEM | EBPF_H): {
			uint64_t store_addr = vm_mmu(vm->reg[ins->dst_reg] + ins->offset, vm);
			*(uint16_t *)store_addr = (uint16_t)vm->reg[ins->src_reg];
			break;
		}
		case (EBPF_CLS_STX | EBPF_MEM | EBPF_W): {
			uint64_t store_addr = vm_mmu(vm->reg[ins->dst_reg] + ins->offset, vm);
			*(uint32_t *)store_addr = (uint32_t)vm->reg[ins->src_reg];
			break;
		}
		case (EBPF_CLS_STX | EBPF_MEM | EBPF_DW): {
			uint64_t store_addr = vm_mmu(vm->reg[ins->dst_reg] + ins->offset, vm);
			*(uint64_t *)store_addr = (uint64_t)vm->reg[ins->src_reg];
			break;
		}
		case (EBPF_CLS_STX | EBPF_XADD | EBPF_W): {
			uint64_t store_addr = vm_mmu(vm->reg[ins->dst_reg] + ins->offset, vm);
			__atomic_fetch_add((uint32_t *)store_addr, (uint32_t)vm->reg[ins->src_reg], __ATOMIC_RELAXED);
			break;
		}
		case (EBPF_CLS_STX | EBPF_XADD | EBPF_DW): {
			uint64_t store_addr = vm_mmu(vm->reg[ins->dst_reg] + ins->offset, vm);
			__atomic_fetch_add((uint64_t *)store_addr, (uint64_t)vm->reg[ins->src_reg], __ATOMIC_RELAXED);
			break;
		}
		case (EBPF_CLS_ST | EBPF_MEM | EBPF_B): {
			uint64_t store_addr = vm_mmu(vm->reg[ins->dst_reg] + ins->offset, vm);
			*(uint8_t *)store_addr = (uint8_t)ins->immediate;
			break;
		}
		case (EBPF_CLS_ST | EBPF_MEM | EBPF_H): {
			uint64_t store_addr = vm_mmu(vm->reg[ins->dst_reg] + ins->offset, vm);
			*(uint16_t *)store_addr = (uint16_t)ins->immediate;
			break;
		}
		case (EBPF_CLS_ST | EBPF_MEM | EBPF_W): {
			uint64_t store_addr = vm_mmu(vm->reg[ins->dst_reg] + ins->offset, vm);
			*(uint32_t *)store_addr = (uint32_t)ins->immediate;
			break;
		}
		case (EBPF_CLS_ST | EBPF_MEM | EBPF_DW): {
			uint64_t store_addr = vm_mmu(vm->reg[ins->dst_reg] + ins->offset, vm);
			*(uint64_t *)store_addr = (uint64_t)ins->immediate;
			break;
		}
		case (EBPF_CLS_ALU | EBPF_ALU_OP_END | EBPF_TO_LE): {
			vm->reg[ins->dst_reg] = to_little_endian(&vm->reg[ins->dst_reg], ins->immediate);
			break;
		}
		case (EBPF_CLS_ALU | EBPF_ALU_OP_END | EBPF_TO_BE): {
			vm->reg[ins->dst_reg] = to_big_endian(&vm->reg[ins->dst_reg], ins->immediate);
			break;
		}
		default: {
			printf("invalid ebpf opcode %x\n", ins->opcode);
			update_vm_state(vm, VM_STATE_EXIT);
			return 0;
		}
		} /*end of switch*/
		/* increase PC */
		ins++;
	} /*end of while*/

	/*should never be here*/
	return 0;
}

static void receive_vm(struct ebpf_vm_executor *executor, void *buf, int buf_size)
{
	struct ebpf_vm *vm = NULL;
	
	if (buf_size < sizeof(struct ebpf_vm)) {
		printf("vm size is too small, buf_size = %d.\n", buf_size);
		return;
	}
	
	vm = calloc(1, buf_size);
	if (vm == NULL) {
		printf("Failed to allocate vm for input vm.\n");
		return;
	}
	
	memcpy(vm, buf, buf_size);
	
	vm->page_table[0].entries[0].va = (uint64_t)vm + vm->data;
	ub_list_init(&vm->address_monitor_list);
	vm->sys_reg[EBPF_SYS_REG_PC]++;
	update_vm_state(vm, VM_STATE_RUNNING);
	
	add_vm(executor, vm);
}

void vm_executor_run(struct ebpf_vm_executor *executor)
{
	struct ebpf_vm *vm = NULL, *tmp = NULL;
	struct transport_message recv_msg;
	int msg_len;
	
	while (executor->state.should_stop == 0) {
		UB_LIST_FOR_EACH_SAFE(vm, tmp, rd.list, &executor->vm_list) {
			if (vm->state.vm_state == VM_STATE_RUNNING ||
				vm->state.vm_state == VM_STATE_WAIT_FOR_ADDRESS) {
					run_ebpf_vm(vm);
			}
			
			if (vm->state.vm_state == VM_STATE_EXIT) {
				ub_list_remove(&vm->rd.list);
				destroy_vm(vm);
			}
		}
		
		msg_len = executor->transport->recv(executor->transport_ctx, &recv_msg);
		if (msg_len != 0) {
			receive_vm(executor, recv_msg.buf, recv_msg.buf_size);
			executor->transport->return_buf(executor->transport_ctx, &recv_msg);
		}
	}
}

int add_vm(struct ebpf_vm_executor *executor, struct ebpf_vm *vm)
{
	vm->rd.id = executor->next_vm_id++;
	vm->rd.symbols = ebpf_global_symbs;
	vm->rd.executor = executor;
	ub_list_push_back(&executor->vm_list, &vm->rd.list);
	return 0;
}

struct ebpf_vm *create_vm(uint8_t *code, uint32_t code_size)
{
	struct ebpf_vm *vm = NULL;
	int total_size = sizeof(struct ebpf_vm);
	
	total_size += code_size;
	total_size += EBPF_VM_DEFAULT_STACK_SIZE;
	total_size += EBPF_VM_DEFAULT_DATA_SIZE;
	
	vm = calloc(1, total_size);
	if (vm == NULL) {
		return NULL;
	}
	
	vm->code_size = code_size;
	vm->stack_size = EBPF_VM_DEFAULT_STACK_SIZE;
	vm->data_size = EBPF_VM_DEFAULT_DATA_SIZE;
	vm->code = sizeof(struct ebpf_vm);
	vm->data = vm->code + vm->code_size;
	vm->stack = vm->data + vm->data_size;
	vm->reg[EBPF_REG_FP] = vm->data_size + vm->stack_size - EBPF_VM_STACK_FRAME_SIZE;
	vm->state.next_data_to_use = 0;
	
	vm->page_table[0].entries[0].va = (uint64_t)vm + vm->data;
	vm->page_table[0].entries[0].size = vm->data_size + vm->stack_size;
	
	memcpy(((uint8_t *)vm + vm->code), code, code_size);
	ub_list_init(&vm->address_monitor_list);
	return vm;
}

void destroy_vm(struct ebpf_vm *vm)
{
	struct address_monitor_entry *entry, *tmp = NULL;
	UB_LIST_FOR_EACH_SAFE(entry, tmp, list, &vm->address_monitor_list){
		ub_list_remove(&entry->list);
		free(entry);
	}
	free(vm);
}

int load_data(struct ebpf_vm *vm, uint8_t *data, uint32_t len)
{
	int remain = vm->data_size - vm->state.next_data_to_use;
	int copy_len = (len < remain) ? len : remain;
	
	if (copy_len != 0) {
		memcpy(((uint8_t *)vm + vm->data + vm->state.next_data_to_use), data, copy_len);
		vm->state.next_data_to_use += copy_len;
	}
	
	return copy_len;
}

int register_transport(struct transport_ops *ops)
{
	registered_transport[ops->type] = ops;
	return 0;
}

void *vm_executor_init(struct ebpf_vm_executor_config *cfg)
{
	struct ebpf_vm_executor *executor = NULL;
	
	executor = malloc(sizeof(*executor));
	if (executor == NULL) {
		perror("Failed to allocate memory");
		return NULL;
	}
	
	ub_list_init(&executor->vm_list);
	executor->state.should_stop = 0;
	executor->transport = registered_transport[PKT_VM_TRANSPORT_TYPE_RDMA];
	executor->transport_ctx = executor->transport->init(&cfg->transport);
	if (executor->transport_ctx == NULL) {
		perror("Failed to initialize transport");
		free(executor);
		return NULL;
	}
	
	return executor;
}

void vm_executor_destroy(struct ebpf_vm_executor *executor)
{
	struct ebpf_vm *vm, *tmp;
	
	if (executor->transport_ctx) {
		executor->transport->exit(executor->transport_ctx);
	}
	
	UB_LIST_FOR_EACH_SAFE(vm, tmp, rd.list, &executor->vm_list){
		ub_list_remove(&vm->rd.list);
		free(vm);
	}
	
	free(executor);
}