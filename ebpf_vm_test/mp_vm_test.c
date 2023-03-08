#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <stdatomic.h>
#include <ctype.h>
#include <pthread.h>
#include <getopt.h>
#include <arpa/inet.h>

#include "mp_vm_test.h"

struct vm_test_config {
	char *vm_file;
	int test_case;
	int act_as_client;
};

static struct vm_test_case *tests[MP_VM_TEST_NUM];

int register_test_case(struct vm_test_case *test)
{
	tests[test->index] = test;
	return 0;
}

static void usage(void)
{
	printf("Usage:\n");
	printf("  -a, --self-ip=<ip>                listen on ip <ip>\n");
	printf("  -p, --self-port=<port>            listen on port <port> (default 18515)\n");
	printf("  -d, --ib-dev=<dev>                use IB device <dev> (default first device found)\n");
	printf("  -i, --ib-port=<port>              use port <port> of IB device (default 1)\n");
	printf("  -s, --size=<size>                 size of message to exchange (default 2048)\n");
	printf("  -r, --rx-depth=<dep>              number of receives to post at a time (default 500)\n");
	printf("  -g, --gid-idx=<gid index>         local port gid index\n");
	printf("  -f, --ebpf-program=<vm file>      path to ebpf program\n");
	printf("  -t, --test-case=<test case index> test case index\n");
	printf("  -c, --client                      act as client\n");
}

static int parse_config(struct vm_test_config *test_cfg,
						struct ebpf_vm_executor_config *executor_cfg,
						int argc, char **argv)
{
	static struct option long_options[] = {
		{.name = "ebpf-program", .has_arg = 1, .val = 'f'},
		{.name = "test-case",    .has_arg = 1, .val = 't'},
		{.name = "self-ip",      .has_arg = 1, .val = 'a'},
		{.name = "self-port",    .has_arg = 1, .val = 'p'},
		{.name = "ib-dev",       .has_arg = 1, .val = 'd'},
		{.name = "ib-port",      .has_arg = 1, .val = 'i'},
		{.name = "msg-size",     .has_arg = 1, .val = 's'},
		{.name = "rx-depth",     .has_arg = 1, .val = 'r'},
		{.name = "gid-idx",      .has_arg = 1, .val = 'g'},
		{.name = "client",       .has_arg = 0, .val = 'c'},
	};
	struct rdma_transport_config *rdma_cfg = &executor_cfg->transport.rdma_cfg;
	
	while (1) {
		int c = getopt_long(argc, argv, "f:t:a:p:d:i:s:r:g:c", long_options, NULL);
		if (c == -1)
			break;
		
		switch (c) {
		case 'f':
			test_cfg->vm_file = strdup(optarg);
			break;

		case 't':
			test_cfg->test_case = strtol(optarg, NULL, 0);
			if (test_cfg->test_case >= MP_VM_TEST_NUM || tests[test_cfg->test_case] == NULL) {
				perror("test case is not supported");
				return 1;
			}
			break;
			
		case 'a':
			inet_pton(AF_INET, optarg, &rdma_cfg->self_url.ip);
			break;
			
		case 'p':
			rdma_cfg->self_url.port = strtol(optarg, NULL, 0);
			rdma_cfg->self_url.port = htons(rdma_cfg->self_url.port);
			break;
			
		case 'd':
			rdma_cfg->ib_devname = strdup(optarg);
			break;
			
		case 'i':
			rdma_cfg->ib_port = strtol(optarg, NULL, 0);
			if (rdma_cfg->ib_port < 1) {
				usage();
				return 1;
			}
			break;
			
		case 's':
			rdma_cfg->max_msg_size = strtoul(optarg, NULL, 0);
			break;
			
		case 'r':
			rdma_cfg->rx_depth = strtoul(optarg, NULL, 0);
			break;
			
		case 'g':
			rdma_cfg->gid_index = strtoul(optarg, NULL, 0);
			break;
			
		case 'c':
			test_cfg->act_as_client = 1;
			break;
		}
	}
	
	executor_cfg->transport.transport_type = PKT_VM_TRANSPORT_TYPE_RDMA;
	return 0;
}

static void say_hello_to(struct ebpf_vm_executor *executor, char *ip, uint16_t port)
{
	struct transport_message send_msg;
	struct node_url dst = {0};
	char msg[64];
	int ret;
	
	inet_pton(AF_INET, ip, &dst.ip);
	dst.port = htons(port);
	
	sprintf(msg, "hello %s", ip);
	send_msg.buf = msg;
	send_msg.buf_size = strlen(msg) + 1;
	
	ret = executor->transport->send(executor->transport_ctx, &dst, &send_msg);
	if (ret != send_msg.buf_size) {
		printf("Message is not sent.\n");
	}
}

static void test_transport(struct ebpf_vm_executor *executor, int act_as_client)
{
	char *ip_str[2] = {"192.168.100.20", "192.168.100.10"};
	int dst_ip_idx = (act_as_client == 1);
	int recv_msg_num = 0;
	int expected_msg_num = 2;
	
	if (act_as_client == 1) {
		say_hello_to(executor, ip_str[dst_ip_idx], 1881);
	}
	
	while (recv_msg_num < expected_msg_num) {
		struct transport_message recv_msg;
		int msg_len = executor->transport->recv(executor->transport_ctx, &recv_msg);
		if (msg_len != 0) {
			recv_msg_num++;
			printf("Received message: %s\n", (char *)recv_msg.buf);
			say_hello_to(executor, ip_str[dst_ip_idx], 1881);
		}
	}
}

int main(int argc, char **argv)
{
	struct ebpf_vm_executor *executor = NULL;
	struct ebpf_vm *vm = NULL;
	struct ebpf_vm_executor_config cfg = {0};
	struct vm_test_config test_cfg = {0};
	void *test_ctx;
	
	if (parse_config(&test_cfg, &cfg, argc, argv) != 0) {
		perror("failed to parse test config");
		return -1;
	}
	
	executor = vm_executor_init(&cfg);
	if (executor == NULL) {
		perror("failed to initialize vm executor");
		return -1;
	}

    if (test_cfg.vm_file != NULL) {
        vm = create_vm_from_elf(test_cfg.vm_file);
        if (vm == NULL) {
            printf("Failed to create ebpf vm from file %s\n", test_cfg.vm_file);
            vm_executor_destroy(executor);
            return -1;
        }
    }

	test_ctx = tests[test_cfg.test_case]->setup(executor, vm, argc, argv);
	if (test_ctx == NULL) {
		destroy_vm(vm);
		vm_executor_destroy(executor);
		return 0;
	}

    if (vm != NULL) {
        add_vm(executor, vm);
    }

	vm_executor_run(executor);

	//test_transport(executor, test_cfg.act_as_client);

	tests[test_cfg.test_case]->teardown(test_ctx);
	vm_executor_destroy(executor);
	return 0;
}

static void *general_test_setup(struct ebpf_vm_executor *executor, struct ebpf_vm *vm, int argc, char **argv)
{
	return (void *)-1;
}

static void general_test_teardown(void *ctx)
{
	return;
}

static struct vm_test_case general_test = {
	.index = MP_VM_TEST_GENERAL,
	.setup = general_test_setup,
	.teardown = general_test_teardown
};

static __attribute__((constructor)) void general_register_test(void)
{
	register_test_case(&general_test);
}