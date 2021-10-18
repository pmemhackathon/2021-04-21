/*
 * RAS.c -- RAS example for the libpmem2
 *
 * This examples demonstrates how a normal application should consume the
 * deep flush and unsafe shutdown count interfaces to provide a reliable
 * and recoverable access to persistent memory resident data structures.
 * It also presents how the application should look for and clear encountered
 * badblocks.
 */

#include <assert.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>

#include <libpmem2.h>

#ifndef _WIN32
#include <unistd.h>
#else
#include <io.h>
#endif

#define DEVICE_ID_LEN			((size_t)512ULL)
#define SOURCE_SIZE 4096

struct device_info {
	char id[DEVICE_ID_LEN];
	uint64_t usc; /* unsafe shutdown count */
};

/*
 * device_info_read -- populates device_info with data
 */
static int
device_info_read(struct device_info *di, struct pmem2_source *src)
{
	/* Obtain device unsafe shutdown counter value (USC). */
	int ret = pmem2_source_device_usc(src, &di->usc);
	if (ret) {
		pmem2_perror("pmem2_source_device_usc");
		return ret;
	}

	/* Calculate the length required for storing device's ID. */
	size_t len = 0;
	ret = pmem2_source_device_id(src, NULL, &len);
	if (ret) {
		pmem2_perror(
			"pmem2_source_device_id failed querying device ID length");
		return ret;
	}

	/* Check if the length is in correct range. */
	if (len > DEVICE_ID_LEN) {
		fprintf(stderr, "the device ID is too long "
			"(%zu > %zu)\n",
			len, DEVICE_ID_LEN);
		return 1;
	}

	/*
	 * Obtain and store a device's ID in the buffer of
	 * previously obtained length.
	 */
	ret = pmem2_source_device_id(src, (char *)&di->id, &len);
	if (ret) {
		pmem2_perror("pmem2_source_device_id failed reading device ID");
		return ret;
	}

	return ret;
}

/*
 * device_info_write -- safely writes new device info into the old location
 */
static int
device_info_write(struct device_info *di_old, const struct device_info *di_new,
	struct pmem2_map *map)
{
	int ret;

	/* First, clear any leftover invalid state from the structure. */
	memset(di_old, 0, sizeof(*di_old));
	ret = pmem2_deep_flush(map, di_old, sizeof(*di_old));
	if (ret) {
		pmem2_perror("pmem2_deep_flush on device_info memset failed");
		return ret;
	}

	/*
	 * Next, write, persist and deep sync the USC value. It has to be stored
	 * on the persistent medium before it will be validated by writing
	 * device ID.
	 */
	di_old->usc = di_new->usc;
	ret = pmem2_deep_flush(map, &di_old->usc, sizeof(di_old->usc));
	if (ret) {
		pmem2_perror("pmem2_deep_flush USC failed");
		return ret;
	}

	/* Valid device ID validates already stored USC value. */
	memcpy(di_old->id, di_new->id, DEVICE_ID_LEN);
	ret = pmem2_deep_flush(map, di_old->id, DEVICE_ID_LEN);
	if (ret) {
		pmem2_perror("pmem2_deep_flush device ID failed");
		return ret;
	}

	return ret;
}

/*
 * device_info_is_initalized -- checks if the content of device info is
 * initialized.
 *
 * This function returns false if device info was never initialized,
 * initialization was interrupted or the file was moved to a different device.
 * Otherwise, the function returns true.
 */
static bool
device_info_is_initalized(const struct device_info *di_old,
	const struct device_info *di_new)
{
	return strncmp(di_new->id, di_old->id, DEVICE_ID_LEN) == 0;
}

/*
 * device_info_is_consistent -- checks if the device info indicates possible
 * silent data corruption.
 *
 * This function returns false if the unsafe shutdown count of the device
 * was incremented since the last open.
 * Otherwise, the function returns true.
 */
static bool
device_info_is_consistent(const struct device_info *di_old,
	const struct device_info *di_new)
{
	return di_old->usc == di_new->usc;
}

#define POOL_SIGNATURE			("SHUTDOWN") /* 8 bytes */
#define POOL_SIGNATURE_LEN		(sizeof(POOL_SIGNATURE))

#define POOL_FLAG_IN_USE		((uint64_t)(1 << 0))
#define POOL_USC_SUPPORTED		((uint64_t)(1 << 1))

#define POOL_VALID_FLAGS (POOL_FLAG_IN_USE | POOL_USC_SUPPORTED)

enum pool_state {
	/*
	 * The pool state cannot be determined because of errors during
	 * retrieval of device information.
	 */
	POOL_STATE_INDETERMINATE,

	/*
	 * The pool is internally consistent and was closed cleanly.
	 * Application can assume that no custom recovery is needed.
	 */
	POOL_STATE_OK,

	/*
	 * The pool is internally consistent, but it was not closed cleanly.
	 * Application must perform consistency checking and custom recovery
	 * on user data.
	 */
	POOL_STATE_OK_BUT_INTERRUPTED,

	/*
	 * The pool can contain invalid data as a result of hardware failure.
	 * Reading the pool is unsafe.
	 */
	POOL_STATE_CORRUPTED,
};

struct pool_header {
	uint8_t signature[POOL_SIGNATURE_LEN];
	uint64_t flags;
	uint64_t size;
	struct device_info info;
};

struct pool_data {
	struct pool_header header;
	char usable_data[];
};

struct pool {
	struct pool_data *data;
	struct pmem2_source *src;
	struct pmem2_map *map;
};

/*
 * pool_new -- creates a new runtime pool instance
 */
static struct pool *
pool_new(int fd)
{
	/* Reserve a memory for the pool. */
	struct pool *pool = malloc(sizeof(struct pool));
	if (pool == NULL)
		goto err_malloc;

	/*
	 * Validate file descriptor and instantiate the object
	 * describing the data source inside the pool struct.
	 */
	int ret = pmem2_source_from_fd(&pool->src, fd);
	if (ret) {
		pmem2_perror("pmem2_source_from_fd");
		goto err_source;
	}

	struct pmem2_config *cfg;
	/* Prepare configuration. */
	ret = pmem2_config_new(&cfg);
	if (ret) {
		pmem2_perror("pmem2_config_new");
		goto err_config;
	}

	/* Set a required granularity parameter in config. */
	ret = pmem2_config_set_required_store_granularity(cfg,
			PMEM2_GRANULARITY_PAGE);
	if (ret) {
		pmem2_perror("pmem2_config_set_required_store_granularity");
		goto err_config_settings;
	}

	/* Prepare the mapping. */
	ret = pmem2_map_new(&pool->map, cfg, pool->src);
	if (ret) {
		pmem2_perror("pmem2_map");
		goto err_map;
	}

	/* Write mapping address to the data field of the pool struct. */
	pool->data = pmem2_map_get_address(pool->map);

	pmem2_config_delete(&cfg);

	return pool;

err_map:
err_config_settings:
	pmem2_config_delete(&cfg);
err_config:
	pmem2_source_delete(&pool->src);
err_source:
	free(pool);
err_malloc:
	return NULL;
}

/*
 * pool_delete -- deletes a runtime pool instance
 */
static void
pool_delete(struct pool *pool)
{
	pmem2_map_delete(&pool->map);
	pmem2_source_delete(&pool->src);
	free(pool);
}

/*
 * pool_set_flag -- safely sets the flag in the pool's header
 */
static int
pool_set_flag(struct pool *pool, uint64_t flag)
{
	uint64_t *flagsp = &pool->data->header.flags;
	*flagsp |= flag;

	/* Flush the flag to the persistent medium. */
	int ret = pmem2_deep_flush(pool->map, flagsp, sizeof(*flagsp));

	return ret;
}

/*
 * pool_clear_flag -- safely clears the flag in the pool's header
 */
static int
pool_clear_flag(struct pool *pool, uint64_t flag)
{
	uint64_t *flagsp = &pool->data->header.flags;
	*flagsp &= ~flag;

	/* Flush the clearance of the flag to the persistent medium. */
	int ret = pmem2_deep_flush(pool->map, flagsp, sizeof(*flagsp));

	return ret;
}

/*
 * pool_header_is_initialized -- checks if all the pool header data is correct
 */
static bool
pool_header_is_initialized(struct pool *pool)
{
	/* Check if the signature is correct. */
	if (memcmp(POOL_SIGNATURE, pool->data->header.signature,
			POOL_SIGNATURE_LEN) != 0)
		return false;

	/* Check if used flags are valid. */
	if (pool->data->header.flags & ~POOL_VALID_FLAGS)
		return false;

	/* Check if the size is correct. */
	if (pool->data->header.size != pmem2_map_get_size(pool->map))
		return false;

	return true;
}

/*
 * pool_header_initialize -- safely initializes the pool header data
 */
static int
pool_header_initialize(struct pool *pool)
{
	struct pool_header *hdrp = &pool->data->header;
	memset(hdrp, 0, sizeof(*hdrp));
	int ret = pmem2_deep_flush(pool->map, hdrp, sizeof(*hdrp));
	if (ret) {
		pmem2_perror("pmem2_deep_flush on device_info memset failed");
		return ret;
	}

	/* Set the size field as a map size and initialize flags as 0. */
	pool->data->header.size = pmem2_map_get_size(pool->map);
	pool->data->header.flags = 0;
	ret = pmem2_deep_flush(pool->map, hdrp, sizeof(*hdrp));
	if (ret) {
		pmem2_perror("pmem2_deep_flush on device_info memset failed");
		return ret;
	}

	/* Set a predifined signature. */
	memcpy(hdrp->signature, POOL_SIGNATURE, POOL_SIGNATURE_LEN);
	ret = pmem2_deep_flush(pool->map, hdrp, sizeof(*hdrp));
	if (ret) {
		pmem2_perror("pmem2_deep_flush on device_info memset failed");
		return ret;
	}

	return 0;
}

/*
 * pool_state_check_and_maybe_init -- verifies various invariants about the pool
 * and returns its state.
 * The pool is initialized if needed.
 */
static enum pool_state
pool_state_check_and_maybe_init(struct pool *pool)
{
	/*
	 * Pool header could not be initialized. Device info cannot be retrieved
	 * so the state_indeterminate error is returned.
	 */
	if (pool_header_is_initialized(pool) != 0) {
		if (pool_header_initialize(pool) != 0)
			return POOL_STATE_INDETERMINATE;
	}

	struct device_info di_new;
	bool in_use = pool->data->header.flags & POOL_FLAG_IN_USE;
	/* If the pool was already in use, it wasn't closed cleanly. */
	enum pool_state state = in_use ?
		POOL_STATE_OK_BUT_INTERRUPTED : POOL_STATE_OK;

	/*
	 * Try to populate the device info with data. NOSUPP error indicates
	 * that USC is not supported on the used platform. If it occurs and the
	 * USC_SUPPORTED flag indicates the usc is not supported as well,
	 * the previously concluded pool state is returned. Otherwise the pool
	 * state is indeterminate. An occurance of any other error while
	 * populating device info also indicates that the pool state
	 * is indeterminate.
	 */
	int ret;
	if ((ret = device_info_read(&di_new, pool->src)) != 0) {
		if (ret == PMEM2_E_NOSUPP) {
			if (pool->data->header.flags & POOL_USC_SUPPORTED)
				return POOL_STATE_INDETERMINATE;
			else
				return state;
		} else {
			return POOL_STATE_INDETERMINATE;
		}
	}

	struct device_info *di_old = &pool->data->header.info;

	bool initialized = device_info_is_initalized(di_old, &di_new);

	if (initialized) {
		/*
		 * Pool is corrupted only if it wasn't closed cleanly and
		 * the device info indicates that device info is inconsistent.
		 */
		if (device_info_is_consistent(di_old, &di_new))
			return state;
		else if (in_use)
			return POOL_STATE_CORRUPTED;

		/*
		 * If device info indicates inconsistency, but the pool was
		 * not in use, we just need to reinitialize the device info.
		 */
		initialized = false;
	}

	/* Initialize the device info if needed. */
	if (!initialized) {
		if (device_info_write(di_old, &di_new, pool->map) != 0)
			return POOL_STATE_INDETERMINATE;
		if (pool_set_flag(pool, POOL_USC_SUPPORTED) != 0)
			return POOL_STATE_INDETERMINATE;
	}

	return state;
}

/*
 * pool_arm -- sets the in use flag, arming the pool state detection mechanism
 */
static int
pool_arm(struct pool *pool)
{
	return pool_set_flag(pool, POOL_FLAG_IN_USE);
}

/*
 * pool_disarm -- tries to deep flush the entire pool and clears the in use flag
 */
static int
pool_disarm(struct pool *pool)
{
	int ret = pmem2_deep_flush(pool->map, pool->data,
		pmem2_map_get_size(pool->map));
	if (ret != 0)
		return ret;

	return pool_clear_flag(pool, POOL_FLAG_IN_USE);
}

/*
 * pool_access_data -- verifies the pool state and, if possible, accesses
 * the pool for reading and writing
 */
static enum pool_state
pool_access_data(struct pool *pool, void **data, size_t *size)
{
	enum pool_state state = pool_state_check_and_maybe_init(pool);

	if (state == POOL_STATE_OK || state == POOL_STATE_OK_BUT_INTERRUPTED) {
		*data = &pool->data->usable_data;
		*size = pmem2_map_get_size(pool->map) -
			sizeof(struct pool_header);

		/* Try to set the pool as in use. */
		if (pool_arm(pool) != 0)
			return POOL_STATE_INDETERMINATE;
	}

	return state;
}

/*
 * pool_access_drop -- drops the access for the pool and marks it as not in use
 */
static void
pool_access_drop(struct pool *pool)
{
	/* Try to unset the pool as in use. */
	if (pool_disarm(pool) != 0) {
		fprintf(stderr,
			"Failed to drop access to pool which might cause inconsistent state during next open.\n");
	}
}

/*
 * pool_get_memcpy -- retrieves the pool's memcpy function
 */
static pmem2_memcpy_fn
pool_get_memcpy(struct pool *pool)
{
	/*
	 * The pool's memcpy function can only be retrieved if the pool
	 * is in use.
	 */
	assert(pool->data->header.flags & POOL_FLAG_IN_USE);
	return pmem2_get_memcpy_fn(pool->map);
}

/*
 * pool_get_memset -- retrieves the pool's memset function
 */
static pmem2_memset_fn
pool_get_memset(struct pool *pool)
{
	/*
	 * The pool's memset function can only be retrieved if the pool
	 * is in use.
	 */
	assert(pool->data->header.flags & POOL_FLAG_IN_USE);
	return pmem2_get_memset_fn(pool->map);
}

/*
 * pool_get_persist -- retrieves the pool's persist function
 */
static pmem2_persist_fn
pool_get_persist(struct pool *pool)
{
	/*
	 * The pool's persist function can only be retrieved if the pool
	 * is in use.
	 */
	assert(pool->data->header.flags & POOL_FLAG_IN_USE);
	return pmem2_get_persist_fn(pool->map);
}

/*
 * badblock_handle -- look for, retrieve information about and
 * clear the encountered bad blocks.
 */
static int
badblock_handle(const struct pmem2_source *src)
{
	/*
	 * Instantiate a bad block context structure, which is used for reading
	 * and clearing bad blocks.
	 */
	struct pmem2_badblock_context *bbctx;
	int ret = pmem2_badblock_context_new(&bbctx, src);
	if (ret) {
		pmem2_perror("pmem2_badblock_context_new");
		return ret;
	}

	/*
	 * Read all the bad blocks from the source and print the message upon
	 * encountering a bad block. Clear all the encountered bad blocks.
	 */
	struct pmem2_badblock bb;
	while ((ret = pmem2_badblock_next(bbctx, &bb)) == 0) {
		printf("encountered bad block at %ld offset with %ld len\n",
				bb.offset, bb.length);
		printf("clearing the bad block\n");
		/* Unmap a bad block and map a new block in its place. */
		ret = pmem2_badblock_clear(bbctx, &bb);
		if (ret) {
			pmem2_perror("pmem2_badblock_clear");
			pmem2_badblock_context_delete(&bbctx);
			return ret;
		}
	}

	/* Clean up. */
	pmem2_badblock_context_delete(&bbctx);

	return 0;
}

/*
 * Define the message to display to the user how to correctly
 * use the program.
 */
#define USAGE_STR "usage: %s <command> <file> [<arg>]\n" \
	"Where available commands are:\n" \
	"\tread - print the file contents\n" \
	"\twrite - store <arg> into the file\n"

/*
 * If the state of the pool is ok, the invariant on this data structure is that
 * the persistent variable is set to 1 only if the string has valid content.
 * If the persistent variable is set to 0, the string should be empty.
 *
 * If the pool state is ok but interrupted, the string variable can contain
 * garbage if persistent variable is set to 0. To restore the previously
 * described invariant, the recovery method needs to zero-out the string if
 * the persistent variable is 0.
 *
 * If the pool state is corrupted, the previous invariants don't hold, and
 * we cannot assume that the string is valid if persistent variable is set to 1.
 * The only correct course of action is to either reinitialize the data or
 * restore from backup.
 */
struct user_data {
	int persistent; /* flag indicates whether buf contains a valid string */
	char buf[]; /* user string */
};

/*
 * user_data_recovery -- this function restores the invariant that if
 * persistent variable is 0, then the string is empty.
 */
static void
user_data_recovery(struct pool *pool,
	struct user_data *data, size_t usable_size)
{
	size_t max_str_size = usable_size - sizeof(data->persistent);

	/* If the persistent flag is set to 0, the string is being cleared. */
	if (!data->persistent)
		pool_get_memset(pool)(data->buf, 0, max_str_size, 0);
}

/*
 * user_data_read -- this function prints out the string.
 *
 * Inside of this method, we can be sure that our invariants hold.
 */
static int
user_data_read(struct pool *pool,
	struct user_data *data, size_t usable_size, void *arg)
{
	/*
	 * If the persistent flag is set to 1, we print the string.
	 * Otherwise, we can be sure that te string is empty and print
	 * the appropriate message.
	 */
	if (data->persistent)
		printf("%s\n", data->buf);
	else
		printf("empty string\n");

	return 0;
}

/*
 * user_data_write -- persistently writes a string to a variable.
 *
 * Inside of this method, we can be sure that our invariants hold.
 */
static int
user_data_write(struct pool *pool,
	struct user_data *data, size_t usable_size, void *arg)
{
	if (arg == NULL) {
		fprintf(stderr, "expected string input argument\n");
		return 1;
	}
	char *str = arg;

	size_t max_str_size = usable_size - sizeof(data->persistent);

	/*
	 * To make sure our invariants hold, we first write the string and then
	 * set the persistent variable to 1. If the string size is larger than
	 * the max size, we return an error.
	 */
	size_t str_size = strlen(str) + 1;
	if (str_size <= max_str_size) {
		pool_get_memcpy(pool)(data->buf, str, str_size, 0);
		data->persistent = 1;
		pool_get_persist(pool)(&data->persistent,
			sizeof(data->persistent));
	} else {
		fprintf(stderr, "string input argument is too large\n");
		return 1;
	}

	return 0;
}

enum user_data_operation_type {
	USER_OP_READ,
	USER_OP_WRITE,

	MAX_USER_OP,
};

typedef int user_data_operation_fn(struct pool *pool,
	struct user_data *data, size_t usable_size, void *arg);

static struct user_data_operation {
	const char *name;
	user_data_operation_fn *fn;
} user_data_operations[MAX_USER_OP] = {
	[USER_OP_READ] = { .name = "read", .fn = user_data_read },
	[USER_OP_WRITE] = { .name = "write", .fn = user_data_write },
};

/*
 * user_data_operation_parse -- parses the user data operation
 */
static struct user_data_operation *
user_data_operation_parse(char *op)
{
	for (int i = 0; i < MAX_USER_OP; ++i) {
		if (strcmp(user_data_operations[i].name, op) == 0)
			return &user_data_operations[i];
	}
	return NULL;
}

int
main(int argc, char *argv[])
{
	/* Parse and validate arguments. */
	if (argc < 3) {
		fprintf(stderr, USAGE_STR, argv[0]);
		return 1;
	}

	char *file = argv[2];

	/* Get the requested user operation. */
	struct user_data_operation *op = user_data_operation_parse(argv[1]);
	if (op == NULL) {
		fprintf(stderr, USAGE_STR, argv[0]);
		return 1;
	}

	/*
	 * Open a file (create if it doesn't exist) and prepare a source.
	 * The file must be opened with read an write permissions.
	 */
	int fd = open(file, O_CREAT | O_RDWR, 0666);
	if (fd < 0) {
		perror(file);
		return 1;
	}

	/*
	 * Truncate the file to the designated size. File handling must be done
	 * manually by the user, when using libpmem2.
	 */
	if (ftruncate(fd, (off_t)SOURCE_SIZE) != 0) {
		perror("ftruncate");
		close(fd);
		return 1;
	}

	/* Open a source from the file. */
	struct pmem2_source *src;
	int ret = pmem2_source_from_fd(&src, fd);
	if (ret) {
		close(fd);
		pmem2_perror("pmem2_source_from_fd");
		return ret;
	}

	/* Handle bad blocks before opening the pool. */
	ret = badblock_handle(src);
	if (ret) {
		close(fd);
		pmem2_source_delete(&src);
		fprintf(stderr, "bad block handling failed\n");
		return ret;
	}

	/* Open a pool from the file. */
	struct pool *pool = pool_new(fd);
	if (pool == NULL) {
		close(fd);
		pmem2_source_delete(&src);
		fprintf(stderr, "unable open a pool from %s", file);
		return 1;
	}

	struct user_data *data;
	size_t size;

	/*
	 * Retrieve the pool state and access the pool for
	 * read and write (if possible).
	 */
	enum pool_state state = pool_access_data(pool, (void **)&data, &size);

	ret = 1;
	switch (state) {
		case POOL_STATE_INDETERMINATE:
		fprintf(stderr,
			"Unable to determine the state of the pool %s. Accessing the pool might be unsafe.\n",
			file);
		goto exit;
		case POOL_STATE_CORRUPTED:
		fprintf(stderr,
			"The pool %s might be corrupted, silent data corruption is possible. Accessing the pool is unsafe.\n",
			file);
		goto exit;
		case POOL_STATE_OK_BUT_INTERRUPTED:
		fprintf(stderr,
			"The pool %s was not closed cleanly. User data recovery is required.\n",
			file);
		user_data_recovery(pool, data, size);
		break;
		case POOL_STATE_OK:
		break;
	}

	/*
	 * Perform read or write operation on the pool data after verifying
	 * the pool state.
	 */
	ret = op->fn(pool, data, size, argv[3]);

	pool_access_drop(pool);

exit:
	pool_delete(pool);

	close(fd);

	pmem2_source_delete(&src);

	return ret;
}
