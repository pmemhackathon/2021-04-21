#include <cassert>
#include <iostream>
#include <libpmemkv.hpp>

using namespace pmem::kv;
using std::cerr;
using std::endl;

// default size for this example: 10 Meg
const uint64_t SIZE = 10 * 1024 * 1024;

//
// open_or_create() is a convenience function to open the
// database if it already exists, or create it with a default
// size if it doesn't.
//
db *open_or_create(const char *path) {

	// start by creating the db object
	db *kv = new db();
	assert(kv != nullptr);

	// create the config information for the pmemkv open
	config cfg;

	// flag to control the behavior for open (create) method
	if (cfg.put_create_if_missing(true) != status::OK) {
		cerr << pmemkv_errormsg() << endl;
		exit(1);
	}

	// specify path of DB
	if (cfg.put_path(path) != status::OK) {
		cerr << pmemkv_errormsg() << endl;
		exit(1);
	}

	// if file doesn't exist, we need to specify size of DB to create
	if (cfg.put_size(SIZE) != status::OK) {
		cerr << pmemkv_errormsg() << endl;
		exit(1);
	}

	if (kv->open("cmap", std::move(cfg)) != status::OK) {
		cerr << pmemkv_errormsg() << endl;
		exit(1);
	}

	return kv;
}
