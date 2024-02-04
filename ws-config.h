/**
 * service options
 **/
#ifndef SVCCONFIG_H
#define SVCCONFIG_H

#include <string>

#define DEF_PORT        50051
#define DEF_ADDRESS     "0.0.0.0"

class ServiceConfig
{
public:
	// start up options
	bool daemonize;				    ///< start as daemon
	int verbosity;	                ///< verbose level: 0- error only, 1- warning, 2- info, 3- debug
	const char *address;			///< HTTP/2 service interface address
	int port;						///< HTTP/2 service interface port
    /// HTTP JSON embedded service
    uint16_t httpJsonPort;
	std::string path;
	bool stopRequest;
	ServiceConfig();
};

#endif
