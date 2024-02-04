#include <cstdlib>
#include <cstring>
#include <cstdio>

#include <sstream>
#include <algorithm>
#include <functional>

#include <sys/stat.h>
#include <microhttpd.h>

static const std::string VERSION_STR("1.0");

// Caution: version may be different, if microhttpd dependecy not compiled, revise version humber
#if MHD_VERSION <= 0x00096600
#define MHD_Result int
#endif
#ifndef MHD_HTTP_HEADER_ACCESS_CONTROL_ALLOW_CREDENTIALS
#define MHD_HTTP_HEADER_ACCESS_CONTROL_ALLOW_CREDENTIALS "Access-Control-Allow-Credentials"
#endif
#ifndef MHD_HTTP_HEADER_ACCESS_CONTROL_ALLOW_METHODS
#define MHD_HTTP_HEADER_ACCESS_CONTROL_ALLOW_METHODS "Access-Control-Allow-Methods"
#endif
#ifndef MHD_HTTP_HEADER_ACCESS_CONTROL_ALLOW_HEADERS
#define MHD_HTTP_HEADER_ACCESS_CONTROL_ALLOW_HEADERS "Access-Control-Allow-Headers"
#endif

#define	LOG_ERR								3
#define	LOG_INFO							5

#define MODULE_WS	200

#include "lora-ws.h"

#define PATH_COUNT 2

enum class RequestType {
    REQUEST_TYPE_VERSION = 0,
    REQUEST_TYPE_CLAUSE = 1,
    REQUEST_TYPE_UNKNOWN = 100
};

class RequestContext {
public:
    RequestType requestType;
    std::string postData;
    RequestContext()
        : requestType(RequestType::REQUEST_TYPE_UNKNOWN) {
    }
};

static const char *paths[PATH_COUNT] = {
    "/version",
    "/clause"
};

const static char *CT_JSON = "text/javascript;charset=UTF-8";
const static char *HDR_CORS_ORIGIN = "*";
const static char *HDR_CORS_CREDENTIALS = "true";
const static char *HDR_CORS_METHODS = "GET,HEAD,OPTIONS,POST,PUT,DELETE";
const static char *HDR_CORS_HEADERS = "Authorization, Access-Control-Allow-Headers, "
    "Origin, Accept, X-Requested-With, Content-Type, Access-Control-Request-Method, Access-Control-Request-Headers";

typedef enum {
	START_FETCH_JSON_OK = 0,
	START_FETCH_FILE = 1
} START_FETCH_DB_RESULT;

const static char *MSG_HTTP_ERROR = "Error";
const static char *MSG404 = "404 not found";
const static char *MSG401 = "Unauthorized";
const static char *MSG501 = "Not immplemented";

const static char *MSG500[5] = {
	"",                                     // 0
	"Error 1",                              // 1
	"Error 2",                              // 2
	"Error 3",                              // 3
	"Error 4"                               // 4
};

static RequestType parseRequestType(const char *url)
{
	int i;
	for (i = 0; i < PATH_COUNT; i++) {
		if (strcmp(paths[i], url) == 0)
			return (RequestType) i;
	}
	return RequestType::REQUEST_TYPE_UNKNOWN;
}

void *uri_logger_callback(void *cls, const char *uri)
{
	return nullptr;
}

const char *NULLSTR = "";

static bool fetchJson(
    std::string &retval,
	struct MHD_Connection *connection,
    const WSConfig *config,
	const RequestContext *env
)
{
    // grpc::ServerContext svcContext;
	switch (env->requestType) {
        case RequestType::REQUEST_TYPE_VERSION:
            retval = "{\"version\": \"" + VERSION_STR + "\"}";;
            break;
        case RequestType::REQUEST_TYPE_CLAUSE:
            retval = "{\"postdata\": \"" + env->postData + "\"}";
            break;
        default:
            return false;
    }
	return true;
}

static void addCORS(MHD_Response *response) {
    MHD_add_response_header(response, MHD_HTTP_HEADER_ACCESS_CONTROL_ALLOW_ORIGIN, HDR_CORS_ORIGIN);
    MHD_add_response_header(response, MHD_HTTP_HEADER_ACCESS_CONTROL_ALLOW_CREDENTIALS, HDR_CORS_CREDENTIALS);
    MHD_add_response_header(response, MHD_HTTP_HEADER_ACCESS_CONTROL_ALLOW_METHODS, HDR_CORS_METHODS);
    MHD_add_response_header(response, MHD_HTTP_HEADER_ACCESS_CONTROL_ALLOW_HEADERS, HDR_CORS_HEADERS);
}

static MHD_Result putStringVector(
    void *retVal,
    enum MHD_ValueKind kind,
    const char *key,
    const char *value
)
{
    std::map<std::string, std::string> *r = (std::map<std::string, std::string> *) retVal;
    r->insert(std::pair<std::string, std::string>(key, value));
    return MHD_YES;
}

static MHD_Result httpError(
    struct MHD_Connection *connection,
    int code
)
{
    struct MHD_Response *response = MHD_create_response_from_buffer(strlen(MSG_HTTP_ERROR), (void *) MSG_HTTP_ERROR, MHD_RESPMEM_PERSISTENT);
    addCORS(response);
    MHD_Result r = MHD_queue_response(connection, code, response);
    MHD_destroy_response(response);
    return r;
}

static MHD_Result httpError401(
    struct MHD_Connection *connection
)
{
    int hc = MHD_HTTP_UNAUTHORIZED;
    struct MHD_Response *response = MHD_create_response_from_buffer(strlen(MSG401), (void *) MSG401, MHD_RESPMEM_PERSISTENT);
    std::string hwa = "Bearer error=\"invalid_token\"";
    MHD_add_response_header(response, MHD_HTTP_HEADER_WWW_AUTHENTICATE, hwa.c_str());
    addCORS(response);
    MHD_Result r = MHD_queue_response(connection, hc, response);
    MHD_destroy_response(response);
    return r;
}

static MHD_Result request_callback(
	void *cls,			// struct WSConfig*
	struct MHD_Connection *connection,
	const char *url,
	const char *method,
	const char *version,
	const char *upload_data,
	size_t *upload_data_size,
	void **ptr
)
{
	struct MHD_Response *response;
	MHD_Result ret;

    if (!*ptr) {
		// do never respond on first call
		*ptr = new RequestContext;
		return MHD_YES;
	}

    if (strcmp(method, "OPTIONS") == 0) {
        response = MHD_create_response_from_buffer(strlen(MSG500[0]), (void *) MSG500[0], MHD_RESPMEM_PERSISTENT);
        MHD_add_response_header(response, MHD_HTTP_HEADER_CONTENT_TYPE, CT_JSON);
        addCORS(response);
        MHD_queue_response(connection, MHD_HTTP_OK, response);
        MHD_destroy_response(response);
        return MHD_YES;
    }

    RequestContext *requestCtx = (RequestContext *) *ptr;
    if (*upload_data_size != 0) {
        requestCtx->postData += std::string(upload_data, *upload_data_size);
        *upload_data_size = 0;
        return MHD_YES;
    }

    requestCtx->requestType = parseRequestType(url);

    int hc;
    if (strcmp(method, "DELETE") == 0) {
        hc = MHD_HTTP_NOT_IMPLEMENTED;
        response = MHD_create_response_from_buffer(strlen(MSG501), (void *) MSG501, MHD_RESPMEM_PERSISTENT);
    } else {
        // Service
        std::string json;
        bool r = fetchJson(json, connection, (WSConfig*) cls, requestCtx);
        if (!r) {
            hc = MHD_HTTP_INTERNAL_SERVER_ERROR;
            response = MHD_create_response_from_buffer(strlen(MSG500[r]), (void *) MSG500[r], MHD_RESPMEM_PERSISTENT);
        } else {
            hc = MHD_HTTP_OK;
            response = MHD_create_response_from_buffer(json.size(), (void *) json.c_str(), MHD_RESPMEM_MUST_COPY);
        }
    }
    MHD_add_response_header(response, MHD_HTTP_HEADER_CONTENT_TYPE, CT_JSON);
    addCORS(response);
	ret = MHD_queue_response(connection, hc, response);
	MHD_destroy_response(response);
    delete requestCtx;
    *ptr = nullptr;
	return ret;
}

bool startWS(
	WSConfig &config
) {
	if (config.flags == 0)
		config.flags = MHD_START_FLAGS;

    struct MHD_Daemon *d = MHD_start_daemon(
		config.flags, config.port, nullptr, nullptr,
		&request_callback, &config,
		MHD_OPTION_CONNECTION_TIMEOUT, (unsigned int) 30,  // 30s timeout
		MHD_OPTION_THREAD_POOL_SIZE, config.threadCount,
		MHD_OPTION_URI_LOG_CALLBACK, &uri_logger_callback, nullptr,
		MHD_OPTION_CONNECTION_LIMIT, config.connectionLimit,
		MHD_OPTION_END
	);
	config.descriptor = (void *) d;
	return config.descriptor != nullptr;
}

void doneWS(
	WSConfig &config
) {
	if (config.descriptor)
		MHD_stop_daemon((struct MHD_Daemon *) config.descriptor);
	config.descriptor = nullptr;
}
