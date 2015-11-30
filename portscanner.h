#ifndef __PORT_SCANNER_H__
#define __PORT_SCANNER_H__

#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <regex.h>   

/**
 * Defining the object portscanner. Useful to save the options in a single object
 */
typedef struct my_port_scanner{
	int min_port;
	int max_port;
	char * host_name;
	unsigned char verbose; //0 = false, >=1 true
	int counter; //Contains number of open ports
}portscanner;

void destroyPortScanner(portscanner * p);
portscanner * newPortScanner();
#endif
