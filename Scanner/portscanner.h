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
#include <netinet/tcp.h>   //Provides declarations for tcp header
#include <netinet/ip.h>    //Provides declarations for ip header

#include <regex.h>   

#include <errno.h>

#include <netdb.h> 
#include <arpa/inet.h>
   

struct pseudo_header    //needed for checksum calculation
{
    unsigned int source_address;
    unsigned int dest_address;
    unsigned char placeholder;
    unsigned char protocol;
    unsigned short tcp_length;
     
    struct tcphdr tcp;
};
 


/**
 * Defining the object portscanner. Useful to save the options in a single object
 */
typedef struct my_port_scanner{
	int min_port;
	int max_port;
	char * host_name;
	unsigned char verbose; //0 = false, >=1 true
	int counter; //Contains number of open ports
	unsigned char method;
}portscanner;



void PortScan (int startPort, int endPort, char* target, int method);
void destroyPortScanner(portscanner * p);
portscanner * newPortScanner();
#endif
