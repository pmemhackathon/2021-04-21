/* SPDX-License-Identifier: BSD-3-Clause */
/* Copyright 2020-2021, Intel Corporation */

/*
 * common.h -- common functions declarations for the example R
 */

#ifndef COMMON_H
#define COMMON_H

#include <string.h>
#include <librpma.h>

#define KILOBYTE	1024

/*
 * Limited by the maximum length of the private data
 * for rdma_connect() in case of RDMA_PS_TCP (28 bytes).
 */
#define DESCRIPTORS_MAX_SIZE 26

struct common_data {
	uint8_t mr_desc_size;	/* size of mr_desc in descriptors[] */
	uint8_t pcfg_desc_size;	/* size of pcfg_desc in descriptors[] */
	/* buffer containing mr_desc and pcfg_desc */
	char descriptors[DESCRIPTORS_MAX_SIZE];
};

int common_peer_via_address(const char *addr,
		enum rpma_util_ibv_context_type type,
		struct rpma_peer **peer_ptr);

#define common_client_peer_via_address(addr, peer_ptr) \
		common_peer_via_address(addr, RPMA_UTIL_IBV_CONTEXT_REMOTE, \
		peer_ptr)

#define common_server_peer_via_address(addr, peer_ptr) \
		common_peer_via_address(addr, RPMA_UTIL_IBV_CONTEXT_LOCAL, \
		peer_ptr)

int common_client_connect(struct rpma_peer *peer, const char *addr,
		const char *port, struct rpma_conn_cfg *cfg,
		struct rpma_conn_private_data *pdata,
		struct rpma_conn **conn_ptr);

int common_server_accept_connection(struct rpma_ep *ep,
		struct rpma_conn_cfg *cfg, struct rpma_conn_private_data *pdata,
		struct rpma_conn **conn_ptr);

int common_wait_for_conn_close_and_disconnect(struct rpma_conn **conn_ptr);
int common_disconnect_and_wait_for_conn_close(struct rpma_conn **conn_ptr);

#endif /* COMMON_H */
