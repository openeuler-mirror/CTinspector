#ifndef _EBPF_VM_SIMULATOR_H_
#define _EBPF_VM_SIMULATOR_H_

#include "ub_list.h"
#include "ebpf_vm_transport.h"

#define EBPF_VM_STACK_DEPTH_MAX 3
#define EBPF_VM_STACK_FRAME_SIZE 64
#define EBPF_VM_DEFAULT_STACK_SIZE 128
#define EBPF_VM_DEFAULT_DATA_SIZE 64
#define PKT_VM_USER_REG_NUM 11
#define PKT_VM_SYS_REG_NUM 4
#define PKT_VM_INVALID_FUNC_IDX 0xffffffff
#define PKT_VM_MAX_SYMBS 256

enum {
	/*00*/ EBPF_REG_RETURN_RESULT,
	/*01*/ EBPF_REG_ARG1,
	/*02*/ EBPF_REG_ARG2,
	/*03*/ EBPF_REG_ARG3,
	/*04*/ EBPF_REG_ARG4,
	/*05*/ EBPF_REG_ARG5,
	/*06*/ EBPF_REG_6,
	/*07*/ EBPF_REG_7,
	/*08*/ EBPF_REG_8,
	/*09*/ EBPF_REG_9,
	/*10*/ EBPF_REG_FP,
};

enum {
	/*00*/ EBPF_SYS_REG_LR,
	/*01*/ EBPF_SYS_REG_PC,
	/*02*/ EBPF_SYS_REG_PAGE_TABLE_IDX,
};

enum {
	EBPF_CLS_LD,   /*0*/
	EBPF_CLS_LDX,  /*1*/
	EBPF_CLS_ST,   /*2*/
	EBPF_CLS_STX,  /*3*/
	EBPF_CLS_ALU,  /*4*/
	EBPF_CLS_JMP,  /*5*/
	EBPF_CLS_RET,  /*6*/
	EBPF_CLS_ALU64 /*7*/
};
#define EBPF_OPCODE_CLASS(code) ((code) & 0x7)

enum {
	EBPF_ALU_OP_ADD  = 0 << 4,
	EBPF_ALU_OP_SUB  = 1 << 4,
	EBPF_ALU_OP_MUL  = 2 << 4,
	EBPF_ALU_OP_DIV  = 3 << 4,
	EBPF_ALU_OP_OR   = 4 << 4,
	EBPF_ALU_OP_AND  = 5 << 4,
	EBPF_ALU_OP_LSH  = 6 << 4,
	EBPF_ALU_OP_RSH  = 7 << 4,
	EBPF_ALU_OP_NEG  = 8 << 4,
	EBPF_ALU_OP_MOD  = 9 << 4,
	EBPF_ALU_OP_XOR  = 10 << 4,
	EBPF_ALU_OP_MOV  = 11 << 4,
	EBPF_ALU_OP_ARSH = 12 << 4,
	EBPF_ALU_OP_END  = 13 << 4
};
#define EBPF_ALU_OP(code) ((code) & 0xf0)

enum {
	EBPF_JMP_OP_JA = 0 << 4,
	EBPF_JMP_OP_JEQ = 1 << 4,
	EBPF_JMP_OP_JGT = 2 << 4,
	EBPF_JMP_OP_JGE = 3 << 4,
	EBPF_JMP_OP_JSET = 4 << 4,
	EBPF_JMP_OP_JNE = 5 << 4,
	EBPF_JMP_OP_JSGT = 6 << 4,
	EBPF_JMP_OP_JSGE = 7 << 4,
	EBPF_JMP_OP_CALL = 8 << 4,
	EBPF_JMP_OP_EXIT = 9 << 4,
	EBPF_JMP_OP_JLT = 10 << 4,
	EBPF_JMP_OP_JLE = 11 << 4,
	EBPF_JMP_OP_JSLT = 12 << 4,
	EBPF_JMP_OP_JSLE = 13 << 4
};
#define EBPF_JMP_OP(code) ((code) & 0xf0)

#define EBPF_SRC_IS_IMM 0x00
#define EBPF_SRC_IS_REG 0x08
#define EBPF_PSEUDO_CALL 1

enum {
	EBPF_W = 0 << 3,
	EBPF_H = 1 << 3,
	EBPF_B = 2 << 3,
	EBPF_DW = 3 << 3,
};
#define EBPF_MEM_SIZE(code) ((code) & 0x18)

enum {
	EBPF_IMM = 0 << 5,
	EBPF_ABS = 1 << 5,
	EBPF_IND = 2 << 5,
	EBPF_MEM = 3 << 5,
	EBPF_LEN = 4 << 5,
	EBPF_MSH = 5 << 5,
	EBPF_XADD = 6 << 5,
};
#define EBPF_MODE(code) ((code) & 0xe0)

#define EBPF_TO_LE 0x00
#define EBPF_TO_BE 0x08

struct ebpf_vm;

struct address_monitor_entry {
	struct ub_list list;
	int type;
	uint64_t address;
	uint64_t value;
	uint64_t tag;
};

typedef uint64_t (*ebpf_external_func)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, struct ebpf_vm *vm);

struct ebpf_symbol {
	const char *name;
	ebpf_external_func func;
};

extern struct ebpf_symbol ebpf_global_symbs[];

struct ebpf_instruction {
	uint8_t opcode;
	uint8_t dst_reg:4;
	uint8_t src_reg:4;
	int16_t offset;
	int32_t immediate;
};

#define EBPF_RAW_INSN(CODE, DST, SRC, OFF, IMM) {CODE, DST, SRC, OFF, IMM}

struct ebpf_vm_executor_config {
	struct transport_config transport;
};

struct executor_state {
	uint32_t should_stop:1;
	uint32_t unused:31;
};

struct ebpf_vm_executor {
	struct ub_list vm_list;
	struct transport_ops *transport;
	void *transport_ctx;
	struct executor_state state;
	uint64_t next_vm_id;
};

enum {
	VM_STATE_RUNNING,
	VM_STATE_EXIT,
	VM_STATE_WAIT_FOR_ADDRESS,
	VM_STATE_MIGRATE_TO,
	VM_STATE_CLONE_TO
};

struct ebpf_vm_state {
	uint8_t stack_depth;
	uint8_t unused;
	uint16_t next_data_to_use;
	uint32_t vm_state;
};

#define ENTRY_MASK 0x00000000ffffffff
#define PACKET_VA_SHIFT 36
#define INDEX_SHIFT 32
#define PAGE_TABLE_ERROR 0xffffffffffffffff
#define PAGE_TABLE_NUM 1
#define BUCKET_ENTRIES 1

struct vm_pte {
	uint64_t va;
	uint64_t size;
};

struct vm_ptb {
	struct vm_pte entries[BUCKET_ENTRIES];
};

struct vm_runtime_data {
	struct ub_list list;
	struct ebpf_vm_executor *executor;
	struct ebpf_symbol *symbols;
	uint64_t id;
};

struct ebpf_vm {
	struct vm_runtime_data rd;
	uint64_t reg[PKT_VM_USER_REG_NUM];
	uint64_t sys_reg[PKT_VM_SYS_REG_NUM];
	uint16_t code;
	uint16_t stack;
	uint16_t data;
	uint16_t code_size;
	uint16_t stack_size;
	uint16_t data_size;
	struct vm_ptb page_table[PAGE_TABLE_NUM];
	struct ebpf_vm_state state;
	struct ub_list address_monitor_list;
};

#define ebpf_vm_code(VM) (struct ebpf_instruction *)((uint8_t *)(VM) + (VM)->code)

struct ebpf_vm *create_vm(uint8_t *code, uint32_t code_size);
struct ebpf_vm *create_vm_from_elf(const char *elf_file_name);
int add_vm(struct ebpf_vm_executor *executor, struct ebpf_vm *vm);
int load_data(struct ebpf_vm *vm, uint8_t *data, uint32_t len);
void destroy_vm(struct ebpf_vm *vm);
void vm_executor_run(struct ebpf_vm_executor *executor);
uint64_t run_ebpf_vm(struct ebpf_vm *vm);
void update_vm_state(struct ebpf_vm *vm, int state);
uint64_t vm_mmu(uint64_t va, struct ebpf_vm *vm);
void *vm_executor_init(struct ebpf_vm_executor_config *cfg);
void vm_executor_destroy(struct ebpf_vm_executor *executor);

#endif /*_EBPF_VM_SIMULATOR_H_*/