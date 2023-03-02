#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <stdatomic.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <libelf.h>

#include "ebpf_vm_simulator.h"

enum {
	MP_ELF_SCN_SYMB,
	MP_ELF_SCN_CODE,
	MP_ELF_SCN_CODE_REL,
	MP_ELF_SCN_MAX
};

struct mp_elf_context {
	Elf *elf;
	Elf64_Ehdr *elf_hdr;
	struct {
		Elf_Scn *scn;
		Elf64_Shdr *hdr;
		const Elf_Data *data;
	} scn[MP_ELF_SCN_MAX];
};

static Elf64_Sym *get_symbol_by_name(struct mp_elf_context *ctx, const char *name)
{
	Elf64_Sym *symbs = ctx->scn[MP_ELF_SCN_SYMB].data->d_buf;
	int symbs_num = ctx->scn[MP_ELF_SCN_SYMB].hdr->sh_size / ctx->scn[MP_ELF_SCN_SYMB].hdr->sh_entsize;
	
	for (int idx = 0; idx < symbs_num; idx++) {
		const char *symb_name = elf_strptr(ctx->elf, ctx->elf_hdr->e_shstrndx, symbs[idx].st_name);
		if (strcmp(symb_name, name) == 0) {
			return &symbs[idx];
		}
	}
	
	return NULL;
}

static uint32_t get_func_idx_by_name(struct ebpf_vm *vm, const char *symb_name)
{
	struct ebpf_symbol *symb = NULL;
	int idx;
	
	if (vm->rd.symbols == NULL) {
		return PKT_VM_INVALID_FUNC_IDX;
	}
	
	for (idx = 0, symb = &vm->rd.symbols[idx];
		 (symb->name != NULL) && (idx < PKT_VM_MAX_SYMBS);
		 symb = &vm->rd.symbols[++idx]) {
		if (strcmp(symb->name, symb_name) == 0) {
			return idx;
		}
	}
	
	return PKT_VM_INVALID_FUNC_IDX;
}

static int32_t get_function_offset(struct mp_elf_context *ctx, const char *func_name)
{
	Elf64_Sym *symb = get_symbol_by_name(ctx, func_name);
	if ((symb == NULL) || ((ELF64_ST_TYPE(symb->st_info)) != STT_FUNC) ||
		(symb->st_shndx != elf_ndxscn(ctx->scn[MP_ELF_SCN_CODE].scn))) {
		return -1;
	}
	
	return symb->st_value / sizeof(struct ebpf_instruction);
}

static void do_relocation(struct ebpf_vm *vm, struct mp_elf_context *ctx)
{
	Elf64_Sym *symbs = ctx->scn[MP_ELF_SCN_SYMB].data->d_buf;
	Elf64_Rel *reloc_entry = ctx->scn[MP_ELF_SCN_CODE_REL].data->d_buf;
	int num_reloc_entry = ctx->scn[MP_ELF_SCN_CODE_REL].data->d_size / sizeof(Elf64_Rel);
	
	for (int idx = 0; idx < num_reloc_entry; idx++) {
		int32_t ins_offset = reloc_entry[idx].r_offset / sizeof(struct ebpf_instruction);
		int sym_idx = ELF64_R_SYM(reloc_entry[idx].r_info);
		const char *symb_name = elf_strptr(ctx->elf, ctx->elf_hdr->e_shstrndx, symbs[sym_idx].st_name);
        int32_t func_offset = get_function_offset(ctx, symb_name);
        if (func_offset >= 0) {
            /*Local function call has higher priority*/
            (ebpf_vm_code(vm))[ins_offset].immediate = (func_offset - ins_offset - 1);
        } else {
            uint32_t func_idx = get_func_idx_by_name(vm, symb_name);
            if (func_idx != PKT_VM_INVALID_FUNC_IDX) {
                (ebpf_vm_code(vm))[ins_offset].immediate = func_idx;
            }
        }
	}
}

static int setup_elf_context(struct mp_elf_context *ctx, int32_t fd)
{
	Elf_Scn *scn = NULL;
	const char *sections[MP_ELF_SCN_MAX] = {".symtab", ".text", ".rel.text"};
	
	elf_version(EV_CURRENT);
	ctx->elf = elf_begin(fd, ELF_C_READ, NULL);
	ctx->elf_hdr = elf64_getehdr(ctx->elf);
	if(ctx->elf_hdr == NULL) {
		printf("Failed to get elf header\n");
		return -1;
	}
	
	while ((scn = elf_nextscn(ctx->elf, scn)) != NULL) {
		Elf64_Shdr *section_hdr = elf64_getshdr(scn);
		const char *section_name = elf_strptr(ctx->elf, ctx->elf_hdr->e_shstrndx, section_hdr->sh_name);
		for (int idx = 0; idx < MP_ELF_SCN_MAX; idx++) {
			if (strcmp(section_name, sections[idx]) == 0) {
				ctx->scn[idx].scn = scn;
				ctx->scn[idx].hdr = section_hdr;
				ctx->scn[idx].data = elf_getdata(scn, NULL);
			}
		}
	}
	
	if (ctx->scn[MP_ELF_SCN_SYMB].scn == NULL || ctx->scn[MP_ELF_SCN_CODE].scn == NULL ||
		ctx->scn[MP_ELF_SCN_CODE].hdr->sh_type != SHT_PROGBITS ||
		ctx->scn[MP_ELF_SCN_CODE].hdr->sh_flags != (SHF_ALLOC | SHF_EXECINSTR) ||
		(ctx->scn[MP_ELF_SCN_CODE_REL].hdr != NULL && ctx->scn[MP_ELF_SCN_CODE_REL].hdr->sh_type != SHT_REL)) {
		return -1;
	}
	
	return 0;
}

struct ebpf_vm *create_vm_from_elf(const char *elf_file_name)
{
	struct ebpf_vm *vm = NULL;
	struct mp_elf_context ctx = {0};
	int32_t fd, main_offset;
	
	fd = open(elf_file_name, O_RDONLY);
	if (fd < 0) {
		printf("Failed to open file %s\n", elf_file_name);
		return NULL;
	}
	
	if (0 != setup_elf_context(&ctx, fd)) {
		printf("Failed to setup elf context\n");
		goto exit_clean;
	}
	
	main_offset = get_function_offset(&ctx, "vm_main");
	if (main_offset < 0) {
		printf("not able to find main function\n");
		goto exit_clean;
	}
	
	vm = create_vm((uint8_t *)ctx.scn[MP_ELF_SCN_CODE].data->d_buf, (uint32_t)ctx.scn[MP_ELF_SCN_CODE].data->d_size);
	if (vm == NULL) {
		printf("Failed to create vm\n");
		goto exit_clean;
	}
	
	vm->sys_reg[EBPF_SYS_REG_PC] = main_offset;
	
	if (ctx.scn[MP_ELF_SCN_CODE_REL].scn != NULL) {
		do_relocation(vm, &ctx);
	}
	
exit_clean:
	if (ctx.elf != NULL) {
		elf_end(ctx.elf);
	}
	
	close(fd);
	return vm;
}