#include "ws-config.h"

ServiceConfig::ServiceConfig()
	: daemonize(false), verbosity(0), address(nullptr),
	port(4242), httpJsonPort(4242), stopRequest(false)
{

}
