#include <string>
#include <cstring>
#include <iostream>
#include <sstream>
#include <csignal>
#include <cstdlib>

#include <argtable3/argtable3.h>

#include "daemonize.h"

#if defined(_MSC_VER) || defined(__MINGW32__)
#include <WinSock2.h>
#include <direct.h>
#define PATH_MAX MAX_PATH
#define sleep Sleep
#define DEF_WAIT 1000
#else
#include <linux/limits.h>
#define DEF_WAIT 1
#endif


// i18n
// #include <libintl.h>
// #define _(String) gettext (String)
#define _(String) (String)

// embedded HTTP service
#include "lora-ws.h"
// print version
#include <microhttpd.h>

#include "log.h"

#if defined(_MSC_VER) || defined(__MINGW32__)
#include <direct.h>
#define PATH_MAX MAX_PATH
#define getcwd _getcwd
#else
#include <unistd.h>
#endif

const char* progname = "lora-ws";

bool stopRequest;

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

static WSConfig wsConfig;

static void stop()
{
    stopRequest = true;
}

static void done()
{
	doneWS(wsConfig);
}

int rslt;

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
        ss << _("Can not start web service errno ")
            << errno << ": " << std::strerror(errno);
		if (asDaemon) {
			SYSLOG(LOG_ALERT, ss.str().c_str());
        } else {
            std::cerr << ss.str() << std::endl;
        }
    } else {
		if (asDaemon) {
			SYSLOG(LOG_ALERT, _("HTTP service successfully started"));
		}
    }
}

static void run() {
    stopRequest = false;
    runHttpJson(wsConfig.port, wsConfig.daemonize);
    while (!stopRequest)
        sleep(3);
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
    WSConfig *value
)
{
	struct arg_str *a_interface = arg_str0("i", "ip4", _("<address>"), _("service IPv4 network interface address. Default 0.0.0.0 (all)"));
	struct arg_lit *a_daemonize = arg_lit0("d", "daemonize", _("start as daemon/service"));
    struct arg_str *a_pidfile = arg_str0("p", "pidfile", _("<file>"), _("Check whether a process has created the file pidfile"));
    struct arg_int *a_port = arg_int0("t", "port", "_(<number>)", _("HTTP service port number. Default 8050"));

    wsConfig.threadCount = NUMBER_OF_THREADS;
    wsConfig.connectionLimit = 1024;

    struct arg_lit *a_verbosity = arg_litn("v", "verbosity", 0, 1, _("-v- verbose"));
	struct arg_lit *a_help = arg_lit0("h", "help", _("Show this help"));
	struct arg_end *a_end = arg_end(20);

	void* argtable[] = { a_interface, a_port, a_daemonize, a_pidfile, a_verbosity, a_help, a_end };

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
		arg_print_glossary(stdout, argtable, "  %-25s %s\n");
		arg_freetable(argtable, sizeof(argtable) / sizeof(argtable[0]));
		return 1;
	}

	if (a_port->count)
		value->port = *a_port->ival;
	else
		value->port = 8050;
    if (a_pidfile->count)
        value->pidfile = *a_pidfile->sval;
    else
        value->pidfile = "";
    value->verbosity = a_verbosity->count;
	value->daemonize = a_daemonize->count > 0;

    arg_freetable(argtable, sizeof(argtable) / sizeof(argtable[0]));

    return 0;
}

#if defined(_MSC_VER) || defined(__MINGW32__)
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
		std::cerr << _("Interrupted..");
        stop();
		done();
		std::cerr << _("exit") << std::endl;
		break;
	default: {
        std::stringstream ss;
        ss << _("Signal ") << signal;
        if (wsConfig.daemonize) {
            SYSLOG(LOG_ALERT, ss.str().c_str());
        } else {
            std::cerr << ss.str() << std::endl;
        }
    }
    }
}

#endif

void setSignalHandler(
    int signal
)
{
#if defined(_MSC_VER) || defined(__MINGW32__)
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
    rslt = 0;
	if (parseCmd(argc, argv, &wsConfig))
		exit(CODE_WRONG_OPTIONS);
	if (wsConfig.daemonize) {
        char wd[PATH_MAX];
		std::string currentPath(getcwd(wd, PATH_MAX));
		if (wsConfig.verbosity)
			std::cerr << _("Start as daemon, use syslog") << std::endl;
        OPEN_SYSLOG(progname)
        SYSLOG(LOG_ALERT, _("Start as daemon"))
        Daemonize daemonize(progname, currentPath, run, stop, done, 0, wsConfig.pidfile);
	}
	else {
		run();
		done();
	}
	return rslt;
}
