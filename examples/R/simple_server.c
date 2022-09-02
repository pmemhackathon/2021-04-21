// SPDX-License-Identifier: BSD-3-Clause
/* Copyright 2021, Intel Corporation */

/*
 * simple_server.c -- a simple connection server
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
	struct rpma_ep *ep = NULL;
	struct rpma_conn *conn = NULL;

	/*
	 * lookup an ibv_context via the address and create a new peer using it
	 */
	ret = common_server_peer_via_address(addr, &peer);
	if (ret)
		return ret;

	/* start a listening endpoint at addr:port */
	ret = rpma_ep_listen(peer, addr, port, &ep);
	if (ret)
		goto err_peer_delete;

	/*
	 * Prepare a connection's private data.
	 * The length of the private data for rdma_connect()
	 * in case of RDMA_PS_TCP is limited to 28 bytes.
	 */
	const char *msg = "Hello client! I'm server :)";
	struct rpma_conn_private_data pdata;
	pdata.ptr = (void *)msg;
	pdata.len = (strlen(msg) + 1) * sizeof(char);

	/*
	 * Wait for an incoming connection request, accept it and wait for its
	 * establishment.
	 */
	ret = common_server_accept_connection(ep, NULL, &pdata, &conn);
	if (ret)
		goto err_ep_shutdown;

	/* here you can use the newly established connection */
	(void) rpma_conn_get_private_data(conn, &pdata);
	if (pdata.ptr) {
		char *msg = pdata.ptr;
		fprintf(stdout, "Server: received the message: %s\n", msg);
	} else {
		fprintf(stdout, "Server: no message received\n");
	}

	/*
	 * Wait for RPMA_CONN_CLOSED, disconnect and delete the connection
	 * structure.
	 */
	ret = common_wait_for_conn_close_and_disconnect(&conn);

err_ep_shutdown:
	/* shutdown the endpoint */
	(void) rpma_ep_shutdown(&ep);

err_peer_delete:
	/* delete the peer object */
	(void) rpma_peer_delete(&peer);

	return ret;
}
