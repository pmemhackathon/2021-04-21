// SPDX-License-Identifier: BSD-3-Clause
/* Copyright 2021, Intel Corporation */

/*
 * simple_client.c -- a simple connection client
 */

#include <stdlib.h>
#include <librpma.h>
#include "common.h"

#define USAGE_STR "usage: %s <server_address> <port>\n"

int
main(int argc, char *argv[])
{
	/* validate parameters */
	if (argc < 3) {
		fprintf(stderr, USAGE_STR, argv[0]);
		exit(-1);
	}

	/* configure logging thresholds to see more details */
	rpma_log_set_threshold(RPMA_LOG_THRESHOLD, RPMA_LOG_LEVEL_INFO);
	rpma_log_set_threshold(RPMA_LOG_THRESHOLD_AUX, RPMA_LOG_LEVEL_INFO);

	/* read common parameters */
	char *addr = argv[1];
	char *port = argv[2];
	int ret;

	/* RPMA resources */
	struct rpma_peer *peer = NULL;
	struct rpma_conn *conn = NULL;

	/*
	 * lookup an ibv_context via the address and create a new peer using it
	 */
	ret = common_client_peer_via_address(addr, &peer);
	if (ret)
		return ret;

	/*
	 * Prepare a connection's private data.
	 * The length of the private data for rdma_connect()
	 * in case of RDMA_PS_TCP is limited to 28 bytes.
	 */
	const char *msg = "Hello server! I'm client :)";
	struct rpma_conn_private_data pdata;
	pdata.ptr = (void *)msg;
	pdata.len = (strlen(msg) + 1) * sizeof(char);

	/* establish a new connection to a server listening at addr:port */
	ret = common_client_connect(peer, addr, port, NULL, &pdata, &conn);
	if (ret)
		goto err_peer_delete;

	/* here you can use the newly established connection */
	(void) rpma_conn_get_private_data(conn, &pdata);
	if (pdata.ptr) {
		char *msg = pdata.ptr;
		fprintf(stdout, "Client: received the message: %s\n", msg);
	} else {
		fprintf(stdout, "Client: no message received\n");
	}

	/*
	 * Disconnect, wait for RPMA_CONN_CLOSED
	 * and delete the connection structure.
	 */
	ret = common_disconnect_and_wait_for_conn_close(&conn);

err_peer_delete:
	/* delete the peer object */
	(void) rpma_peer_delete(&peer);

	return ret;
}
