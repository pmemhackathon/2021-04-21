#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#ifndef _WIN32
#include <unistd.h>
#else
#include <io.h>
#endif
#include <libpmem2.h>

#define MAP_LEN 4096

int
main(int argc, char *argv[])
{
    int fd;
	char *mapaddr;
	size_t map_size;
	struct pmem2_config *cfg;
	struct pmem2_map *map;
	struct pmem2_source *src;
	pmem2_persist_fn persist;
	pmem2_memcpy_fn memcpy_fn;

	if (argc != 2) {
		fprintf(stderr, "Usage: %s filename\n", argv[0]);
		exit(1);
	}

	/* The user is responsible for handling files when using libpmem2.
     *
	 * Open the file specified by the first argument passed to the program.
	 * If the file doesn't exist, it is created.
	*/
	if ((fd = open(argv[1], O_CREAT|O_RDWR, 0666)) < 0) {
		perror("open");
		exit(1);
	}

	/* Truncate the file to the MAP_LEN */
	if (ftruncate(fd, (off_t)MAP_LEN) != 0) {
		perror("ftruncate");
		close(fd);
		exit(1);
	}

	/* Create config, which defines parameters for creating map. */
	int ret = pmem2_config_new(&cfg);
	if (ret) {
		pmem2_perror("pmem2_config_new");
		close(fd);
		exit(1);
	}

	/* Retrieve source from file. */
	ret = pmem2_source_from_fd(&src, fd);
	if (ret) {
		pmem2_perror("pmem2_source_from_fd");
		goto exit_cfg_del;
	}

	/* Set max permitted granularity to granularity_page.
	 * Granularity is autodetected, mappings with a lower
	 * granularity than the requested one can be created as well.
	 * Granularity is the only required parameter in config set.
	*/
	ret = pmem2_config_set_required_store_granularity(cfg,
			PMEM2_GRANULARITY_PAGE);
	if (ret) {
		pmem2_perror("pmem2_config_set_required_store_granularity");
		goto exit_src_del;
	}

	/* Memory map the source with the parameters set in config
	 * and create the mapping in the virtual address space.
	 * By default, the length used for mapping equals the size
	 * of the source file.
	*/
	ret = pmem2_map_new(&map, cfg, src);
	if (ret) {
		pmem2_perror("pmem2_map");
		goto exit_src_del;
	}

	/* Retrieve a map address. */
	mapaddr = pmem2_map_get_address(map);
	/* Retrieve a map size. */
	map_size = pmem2_map_get_size(map);

	/* Store a string to the persistent memory. */
	char s[] = "This is new data written to the file";
	strcpy(mapaddr, s);

	/*
	 * Flush our string to persistence, libpmem2 automatically
	 * decides the correct mechanism for flushing the data
	 * onto the underlying storage.
	 */
	persist = pmem2_get_persist_fn(map);
	persist(mapaddr, map_size);

	/*
	 * The above steps, copying something to memory and flushing it
	 * to persistence, are so common libpmem2 provides optimized ways
	 * to do it.
	 */
	memcpy_fn = pmem2_get_memcpy_fn(map);
    memcpy_fn(mapaddr, s, sizeof(s), 0);

	/* unmap the file and clean up */
	pmem2_map_delete(&map);
	exit_src_del:
		pmem2_source_delete(&src);
	exit_cfg_del:
		pmem2_config_delete(&cfg);

	close(fd);

	printf("done.\n");
	return ret;
}
