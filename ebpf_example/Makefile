CFLAGS=-O2 -fno-inline -emit-llvm -I../ebpf_vm_executor
LINKFLAGS=-march=bpf -filetype=obj

all: vm_mmap.o vm_monitor_address.o vm_function_call.o vm_migrate.o vm_clone.o

vm_mmap.o:
	clang $(CFLAGS) -c mmap.c -o - | llc $(LINKFLAGS) -o vm_mmap.o

vm_monitor_address.o:
	clang $(CFLAGS) -c monitor_address.c -o - | llc $(LINKFLAGS) -o vm_monitor_address.o

vm_function_call.o:
	clang $(CFLAGS) -c function_call.c -o - | llc $(LINKFLAGS) -o vm_function_call.o

vm_migrate.o:
	clang $(CFLAGS) -c migrate.c -o - | llc $(LINKFLAGS) -o vm_migrate.o

vm_clone.o:
	clang $(CFLAGS) -c clone.c -o - | llc $(LINKFLAGS) -o vm_clone.o

clean:
	rm -f vm_mmap.o vm_monitor_address.o vm_function_call.o vm_migrate.o vm_clone.o
