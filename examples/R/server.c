// SPDX-License-Identifier: BSD-3-Clause
/* Copyright 2020-2021, Intel Corporation */

/*
 * server.c -- a server of the "read, write and flush to persistent domain" example
 */

#include <stdlib.h>
#include <libpmem.h>
#include <librpma.h>
#include "common.h"

#define USAGE_STR	"usage: %s <server_address> <port> <pmem-path> <user-id>\n"
#define INIT_STR	"This is the initial server string."
#define MAX_USERS	200
#define PMEM_MIN_SIZE	(MAX_USERS * 4 * KILOBYTE) /* 4KiB for each user */

#define ERROR_ON_WRONG_USAGE(cond) \
	do { \
		if (cond) { \
			fprintf(stderr, USAGE_STR, argv[0]); \
			exit(-1); \
		} \
	} while (0)

int
main(int argc, char *argv[])
{
	int ret;

	/* configure logging thresholds to see more details */
	rpma_log_set_threshold(RPMA_LOG_THRESHOLD, RPMA_LOG_LEVEL_INFO);
	rpma_log_set_threshold(RPMA_LOG_THRESHOLD_AUX, RPMA_LOG_LEVEL_INFO);

	/* validate parameters */
	ERROR_ON_WRONG_USAGE(argc < 5);

	/* read parameters */
	char *addr = argv[1];
	char *port = argv[2];
	char *path = argv[3];
	int user_id = atoi(argv[4]);

	ERROR_ON_WRONG_USAGE(user_id < 1 || user_id > MAX_USERS);

	/* resources - PMem */
	char *pmem_ptr;
	size_t pmem_size;
	int is_pmem;

	/* map the file */
	pmem_ptr = pmem_map_file(path, 0 /* len */, 0 /* flags */,
			0 /* mode */, &pmem_size, &is_pmem);
	if (pmem_ptr == NULL) {
		(void) fprintf(stderr, "Server: error: pmem_map_file() for %s failed\n", path);
		return -1;
	}

	/* pmem is expected */
	if (!is_pmem) {
		(void) fprintf(stderr, "Server: error: %s is not an actual PMEM\n", path);
		(void) pmem_unmap(pmem_ptr, pmem_size);
		return -1;
	}

	/* check if PMem has minimum required size */
	if (pmem_size < PMEM_MIN_SIZE) {
		(void) fprintf(stderr, "Server: error: %s too small (%zu < %u)\n",
				path, pmem_size, PMEM_MIN_SIZE);
		(void) pmem_unmap(pmem_ptr, pmem_size);
		return -1;
	}

	/* resources - memory region */
	struct rpma_mr_local *mr = NULL;
	/* separate 4KiB of PMem for each user */
	size_t mr_size = 4 * KILOBYTE;
	char *mr_ptr = pmem_ptr + (user_id - 1) * mr_size;

	/* RPMA resources */
	struct rpma_peer_cfg *pcfg = NULL;
	struct rpma_peer *peer = NULL;
	struct rpma_ep *ep = NULL;
	struct rpma_conn *conn = NULL;

	/* set and print the initial content */
	strncpy(mr_ptr, INIT_STR, mr_size);
	(void) printf("Server: the initial content of the server's persistent memory: %s\n",
			mr_ptr);
	/*
	 * Flush the output buffer in order to assure the initial value
	 * will be really close to the top of the console
	 * in the case of mixing the client and the server output.
	 */
	(void) fflush(stdout);

	/* create a peer configuration structure */
	ret = rpma_peer_cfg_new(&pcfg);
	if (ret)
		goto err_unmap;

	/* configure peer's direct write to pmem support */
	ret = rpma_peer_cfg_set_direct_write_to_pmem(pcfg, true);
	if (ret) {
		(void) rpma_peer_cfg_delete(&pcfg);
		goto err_unmap;
	}

	/*
	 * lookup an ibv_context via the address and create a new peer using it
	 */
	ret = common_server_peer_via_address(addr, &peer);
	if (ret)
		goto err_pcfg_delete;

	/* start a listening endpoint at addr:port */
	ret = rpma_ep_listen(peer, addr, port, &ep);
	if (ret)
		goto err_peer_delete;

	/* register the memory */
	ret = rpma_mr_reg(peer, mr_ptr, mr_size,
			RPMA_MR_USAGE_READ_SRC | RPMA_MR_USAGE_WRITE_DST |
			(RPMA_MR_USAGE_FLUSH_TYPE_PERSISTENT |
				RPMA_MR_USAGE_FLUSH_TYPE_VISIBILITY),
			&mr);
	if (ret)
		goto err_ep_shutdown;

	/* get size of the memory region's descriptor */
	size_t mr_desc_size;
	ret = rpma_mr_get_descriptor_size(mr, &mr_desc_size);
	if (ret)
		goto err_mr_dereg;

	/* get size of the peer config descriptor */
	size_t pcfg_desc_size;
	ret = rpma_peer_cfg_get_descriptor_size(pcfg, &pcfg_desc_size);
	if (ret)
		goto err_mr_dereg;

	/* calculate data for the client write */
	struct common_data data = {0};
	data.mr_desc_size = mr_desc_size;
	data.pcfg_desc_size = pcfg_desc_size;

	/* get the memory region's descriptor */
	ret = rpma_mr_get_descriptor(mr, &data.descriptors[0]);
	if (ret)
		goto err_mr_dereg;

	/*
	 * Get the peer's configuration descriptor.
	 * The pcfg_desc descriptor is saved in the `descriptors[]` array
	 * just after the mr_desc descriptor.
	 */
	ret = rpma_peer_cfg_get_descriptor(pcfg,
			&data.descriptors[mr_desc_size]);
	if (ret)
		goto err_mr_dereg;

	/*
	 * Wait for an incoming connection request, accept it and wait for its
	 * establishment.
	 */
	struct rpma_conn_private_data pdata;
	pdata.ptr = &data;
	pdata.len = sizeof(struct common_data);
	ret = common_server_accept_connection(ep, NULL, &pdata, &conn);
	if (ret)
		goto err_mr_dereg;

	/*
	 * Wait for RPMA_CONN_CLOSED, disconnect and delete the connection
	 * structure.
	 */
	ret = common_wait_for_conn_close_and_disconnect(&conn);
	if (ret)
		goto err_mr_dereg;

	(void) printf("Server: read a new data from the server's persistent memory: %s\n",
			mr_ptr);

err_mr_dereg:
	/* deregister the memory region */
	(void) rpma_mr_dereg(&mr);

err_ep_shutdown:
	/* shutdown the endpoint */
	(void) rpma_ep_shutdown(&ep);

err_peer_delete:
	/* delete the peer object */
	(void) rpma_peer_delete(&peer);

err_pcfg_delete:
	(void) rpma_peer_cfg_delete(&pcfg);

err_unmap:
	(void) pmem_unmap(mr_ptr, mr_size);

	return ret;
}
