#ifndef _EBPF_VM_TRANSPORT_RDMA_H_
#define _EBPF_VM_TRANSPORT_RDMA_H_

#include "ebpf_vm_transport.h"

#define EXCH_MSG_PATTERN "0000:000000:000000:00000000000000000000000000000000"
#define GID_STR_SIZE 33
#define UD_GRH_SIZE 40

enum {
	PKT_VM_RDMA_RECV_WRID = 1,
	PKT_VM_RDMA_SEND_WRID = 2
};

struct rdma_addr_message {
	int lid;
	int qpn;
	int psn;
	union ibv_gid gid;
};

struct rdma_addr_info {
	struct ub_list node;
	struct node_url key;
	struct rdma_addr_message info;
	struct ibv_ah *ah;
};

struct pkt_vm_rdma_state {
	uint32_t pending:1;
	uint32_t should_stop:1;
	uint32_t unused:30;
};

struct pkt_vm_rdma_context {
	struct rdma_transport_config cfg;
	struct ibv_context *context;
	struct ibv_comp_channel *channel;
	struct ibv_pd *pd;
	struct ibv_mr *mr;
	struct ibv_cq *cq;
	struct ibv_qp *qp;
	char *buf;
	int buf_size;
	char *send_buf;
	int send_offset;
	int send_flags;
	int rx_depth;
	pthread_t server_thread;
	struct pkt_vm_rdma_state state;
	struct ibv_port_attr portinfo;
	struct rdma_addr_message local_addr;
	struct ub_list dst_addr_list;
};

#endif