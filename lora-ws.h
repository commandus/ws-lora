/*
 * @file lora-ws.h
 */

#ifndef LORA_WS_H_
#define LORA_WS_H_	1

#include <map>
#include <string>

#include "query-parser-json.h"

#define MHD_START_FLAGS 	MHD_USE_POLL | MHD_USE_INTERNAL_POLLING_THREAD | MHD_USE_SUPPRESS_DATE_NO_CLOCK | MHD_USE_TCP_FASTOPEN | MHD_USE_TURBO

#define NUMBER_OF_THREADS CPU_COUNT

/**
 * Configuration to start up web service
 */
class WSConfig {
public:
	size_t threadCount;
    size_t connectionLimit;
	unsigned int flags;

	// listener port
	int port;
	// last error code
	int lasterr;
	// log verbosity
	int verbosity;
    // daemon
    bool daemonize;
	// web server descriptor
	void *descriptor;
    //
    QueryParserJson queryParserJson;
};

/**
 * @param threadCount threads count, e.g. 2
 * @param connectionLimit mex connection limit, e.g. 1000
 * @param flags e.g. MHD_SUPPRESS_DATE_NO_CLOCK | MHD_USE_DEBUG | MHD_USE_SELECT_INTERNALLY
 * @param config listener descriptors, port number
 */ 
bool startWS(
	WSConfig &config
);

void doneWS(
	WSConfig &config
);

#endif
