/* 
 * web service
 * Usage:
 * ./ws-lora
 */

#include <string>
#include <iostream>
#include <sstream>

#include <csignal>
#include <cstdlib>
#include <argtable3/argtable3.h>

#include "daemonize.h"

#ifdef _MSC_VER
#include <WinSock2.h>
#include <direct.h>
#define PATH_MAX MAX_PATH
#define sleep Sleep
#define DEF_WAIT 1000
#else
#define DEF_WAIT 1
#endif


// i18n
// #include <libintl.h>
// #define _(String) gettext (String)
#define _(String) (String)

// embedded HTTP service
#include "lora-ws.h"
#include "ws-config.h"
// print version
#include <microhttpd.h>

#include "log.h"

#ifdef _MSC_VER
#include <direct.h>
#define PATH_MAX MAX_PATH
#define getcwd _getcwd
#else
#include <unistd.h>
#endif

const char* progname = "lora-ws";

/**
 * Number of threads to run in the thread pool.  Should (roughly) match
 * the number of cores on your system.
 */

#if defined(CPU_COUNT) && (CPU_COUNT+0) < 2
#undef CPU_COUNT
#endif
#if !defined(CPU_COUNT)
#define CPU_COUNT 2
#endif

#define NUMBER_OF_THREADS CPU_COUNT

#define CODE_WRONG_OPTIONS              1

typedef void (*TDaemonRunner)();

static ServiceConfig config;		//<	program configuration read from command line
static WSConfig wsConfig;

bool stopRequest = false;
bool stopBookingRequest = false;


void stopNWait()
{
	stopRequest = true;
	stopBookingRequest = true;
}

void done()
{
	doneWS(wsConfig);
}

int reslt;

static void runHttpJson(
    uint16_t port,
    bool asDaemon
)
{
    if (asDaemon)
        SYSLOG(LOG_ALERT, "Start HTTP service")

    wsConfig.descriptor = nullptr;
    wsConfig.flags = 0;
    wsConfig.lasterr = 0;
    wsConfig.port = port;
    if (!startWS(wsConfig)) {
        std::stringstream ss;
        ss << "Can not start web service errno "
            << errno << ": " << strerror(errno)
            << ". libmicrohttpd version " << std::hex << MHD_VERSION;
		if (asDaemon) {
			SYSLOG(LOG_ALERT, ss.str().c_str());
        } else {
            std::cerr << ss.str() << std::endl;
        }
    } else {
		if (asDaemon) {
			SYSLOG(LOG_ALERT, "HTTP service successfully started");
		}
    }
}

static void run() {
    runHttpJson(config.httpJsonPort, config.daemonize);
	std::string l;
	while (!config.stopRequest) {
		sleep(DEF_WAIT);
	}
}


/**
 * Parse command line into ServiceConfig
 * Return 0- success
 *        1- show help and exit, or command syntax error
 *        2- output file does not exists or can not open to write
 **/
int parseCmd(
	int argc,
	char* argv[],
	ServiceConfig *value
)
{
	struct arg_str *a_interface = arg_str0("i", "ip4", _("<address>"), _("service IPv4 network interface address. Default 0.0.0.0 (all)"));
	struct arg_int *a_port = arg_int0("l", "listen", _("<port>"), _("service port. Default 50051"));
	struct arg_lit *a_daemonize = arg_lit0("d", "daemonize", _("start as daemon/service"));
    struct arg_int *a_http_json_port = arg_int0("p", "port", "_(<number>)", _("HTTP service port number. Default 8050"));

    wsConfig.threadCount = NUMBER_OF_THREADS;
    wsConfig.connectionLimit = 1024;

    struct arg_lit *a_verbosity = arg_litn("v", "verbosity", 0, 1, _("-v- verbose"));
	struct arg_lit *a_help = arg_lit0("h", "help", _("Show this help"));
	struct arg_end *a_end = arg_end(20);

	void* argtable[] = { a_interface, a_port,
        a_http_json_port,
        a_daemonize,
        a_verbosity,
        a_help, a_end
    };

	int nerrors;

	// verify the argtable[] entries were allocated successfully
	if (arg_nullcheck(argtable) != 0) {
		arg_freetable(argtable, sizeof(argtable) / sizeof(argtable[0]));
		return 1;
	}
	// Parse the command line as defined by argtable[]
	nerrors = arg_parse(argc, argv, argtable);

	// special case: '--help' takes precedence over error reporting
	if ((a_help->count) || nerrors)	{
		if (nerrors)
			arg_print_errors(stderr, a_end, progname);
		std::cout << _("Usage: ") << progname << std::endl;
		arg_print_syntax(stdout, argtable, "\n");
		std::cout << _("rcr GRPC service") << std::endl;
		arg_print_glossary(stdout, argtable, "  %-25s %s\n");
		arg_freetable(argtable, sizeof(argtable) / sizeof(argtable[0]));
		return 1;
	}

	if (a_interface->count)
		value->address = *a_interface->sval;
	else
		value->address = DEF_ADDRESS;
	if (a_port->count)
		value->port = *a_port->ival;
	else
		value->port = DEF_PORT;
    value->verbosity = a_verbosity->count;

    value->httpJsonPort = 8050;
    if (a_http_json_port->count)
        value->httpJsonPort = *a_http_json_port->ival;

	value->daemonize = a_daemonize->count > 0;
	arg_freetable(argtable, sizeof(argtable) / sizeof(argtable[0]));

#ifdef _MSC_VER
	char wd[MAX_PATH];
	GetCurrentDirectoryA(MAX_PATH - 1, wd);
#else
	char wd[PATH_MAX];
	value->path = getcwd(wd, PATH_MAX);
#endif
    return 0;
}

#ifdef _MSC_VER
BOOL WINAPI winSignallHandler(DWORD fdwCtrlType)
{
	switch (fdwCtrlType) {
		// Handle the CTRL-C signal.
	case CTRL_C_EVENT:
	case CTRL_CLOSE_EVENT:
		done();
		return FALSE;
	case CTRL_BREAK_EVENT:
	case CTRL_LOGOFF_EVENT:
	case CTRL_SHUTDOWN_EVENT:
		done();
		return FALSE;
	default:
		return FALSE;
	}
}
#else
void signalHandler(int signal)
{
	switch (signal)
	{
	case SIGINT:
		config.stopRequest = true;
		std::cerr << _("Interrupted..");
		stopNWait();
		done();
		std::cerr << _("exit") << std::endl;
		break;
	default:
		std::cerr << _("Signal ") << signal << std::endl;
	}
}
#endif

void setSignalHandler(
    int signal
)
{
#ifdef _MSC_VER
	SetConsoleCtrlHandler(winSignallHandler, TRUE);
#else
	struct sigaction action;
	memset(&action, 0, sizeof(struct sigaction));
	action.sa_handler = &signalHandler;
	sigaction(signal, &action, nullptr);
#endif
}

int main(int argc, char* argv[])
{
	// Signal handler
	setSignalHandler(SIGINT);
	reslt = 0;
	if (parseCmd(argc, argv, &config))
		exit(CODE_WRONG_OPTIONS);
	if (config.daemonize) {
        char wd[PATH_MAX];
        std::string currentPath = getcwd(wd, PATH_MAX);
		if (config.verbosity)
			std::cerr << _("Start as daemon, use syslog") << std::endl;
        OPEN_SYSLOG(progname)
        SYSLOG(LOG_ALERT, _("Start as daemon"))
        Daemonize daemonize(progname, currentPath, run, stopNWait, done);
	}
	else {
		run();
		done();
	}
	return reslt;
}
