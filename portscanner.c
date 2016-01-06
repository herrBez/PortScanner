/*
 * portscanner.c
 * Main File of the project portscanner at the university of Innsbruck
 * Course: Angewandte Informationssicherheit
 *
 * 
 */

//#include <arpa/inet.h>
#include "portscanner.h"
#include "raw_socket_scan.h"




void printHelp(char * program_name){
	printf("================================\n");
	printf("=== Portscanner help message ===\n");
	printf("================================\n");
	printf("Usage: %s [options]\n", program_name);
	printf("Options:\n\n");
	printf("\t -h \t print this help and exit\n");
	printf("\t -p \t specify a port range in form min-max (Defualt 1-65535)\n");
	printf("\t -u \t specify a url to scan (Default localhost)\n");
	printf("\t -v \t verbose output\n");
	printf("\t -s \t perform a Syn scan\n");
	printf("\t -n \t perform a NULL scan\n");
	printf("\t -f \t perform a FIN scan\n");
	printf("\t -x \t perform a XMAS scan\n");

	printf("\nAuthors: Simon Targa, Mirko Bez\n");
	exit(EXIT_SUCCESS);
}

void destroyPortScanner(portscanner * p){
	printf("Clean up...\n");
	free(p->host_name);
	free(p);
}

void parsePort(char * ports, portscanner * p){
	printf("Parsing ports: %s\n", ports);
	char * tmp;
	tmp = strtok(ports, "-");
	if(tmp == NULL)
		perror("Parse Port");
	p->min_port = strtol(tmp, NULL, 0);
	tmp = strtok(NULL, "-");
	p->max_port = strtol(tmp, NULL, 0);
	if(p->min_port > p->max_port){
		fprintf(stderr, "Min Port %d > Max Port %d. Exiting\n", p->min_port, p->max_port);
		destroyPortScanner(p);
		exit(EXIT_FAILURE);
	}
}

void getOptions(int argc, char * argv[], portscanner * p){
	int opt;
	while((opt = getopt(argc, argv, "phuvsnfx")) != -1) {
		switch(opt){
			case 'p': parsePort(argv[optind], p); break;
			case 'h': printHelp(argv[0]); break;
			case 'u': free(p->host_name); p->host_name = strdup(argv[optind]); break;
			case 'v': p->verbose = 1; break;
			case 's': p->method = 1; break;
			case 'n': p->method = 2; break;
			case 'f': p->method = 3; break;
			case 'x' : p->method = 4; break;
		}
	}
}

portscanner * newPortScanner(){
	portscanner * p = malloc(sizeof(portscanner));
	p->min_port = 1;
	p->max_port = 1024;
	p->host_name = strdup("localhost");
	p->verbose = 0;
	p->counter = 0;
	p->method = 0; //TCP-Scanner
	return p;
}



void TCPScan(portscanner * p){
	printf("Scanning %s using TCP Scan\n", p->host_name);
	printf("Range of ports = %d --> %d \n\n", p->min_port, p->max_port);

	
	int i = 0;
    struct sockaddr_in server;
	int mysocket;
	struct hostent *hostname;

	mysocket = socket(AF_INET, SOCK_STREAM, 0);

    memset(&server, 0, sizeof (server));
	/** N.B. GETHOSTBYNAME IS OBSOLETE */
    hostname = gethostbyname(p->host_name);
	printf("ADDRR[%d] ?? %s\n", hostname->h_length, hostname->h_addr_list[0]);


    memcpy( (char *)&server.sin_addr, hostname->h_addr_list[0], hostname->h_length);
    server.sin_family = AF_INET;
    
    if(p->verbose)
		printf("\n");

	
	int interval = p->max_port - p->min_port + 1;//Because of <=
   
	
    for(i = p->min_port; i <= p->max_port; i++){	
		if(p->verbose)
			printf("\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\bScanning port %6d from %6d", i, interval);
		
		
		
		server.sin_port = htons(i);
		if(connect(mysocket, (struct sockaddr *)&server, sizeof(server))<0){
			//perror("connect");
			//return EXIT_FAILURE;
		}
		else{
			if(p->verbose)
				printf("\n");
			printf("TCP - Port %d is open\n", i);
			close(mysocket);
			mysocket = socket(AF_INET, SOCK_STREAM, 0);
			p->counter++;
			sleep(1);
		}
	
	} 
	if(p->verbose)
		printf("\n");
	
	
	/* Printing results */
	printf("\n%d Ports in range [%d,%d] are open on Host '%s'\n", p->counter, p->min_port, p->max_port, p->host_name);

	
}



void SYNScan(portscanner * p){
	printf("Scanning %s using SYN Scan\n", p->host_name);
	printf("Range of ports = %d --> %d \n\n", p->min_port, p->max_port);
	PortScan(p->min_port, p->max_port, p->host_name, 0);
	/* CREATING THE RAW SOCKET */
	//int s = socket (AF_INET, SOCK_RAW , IPPROTO_TCP);
}





void NullScan(portscanner * p){
	printf("Scanning %s using NULL Scan\n", p->host_name);
	printf("Range of ports = %d --> %d \n\n", p->min_port, p->max_port);
	PortScan(p->min_port, p->max_port, p->host_name, 1);
	/* CREATING THE RAW SOCKET */
	//int s = socket (AF_INET, SOCK_RAW , IPPROTO_TCP);
}

void FinScan(portscanner * p){
	printf("Scanning %s using FIN Scan\n", p->host_name);
	printf("Range of ports = %d --> %d \n\n", p->min_port, p->max_port);
	PortScan(p->min_port, p->max_port, p->host_name, 2);
	/* CREATING THE RAW SOCKET */
	//int s = socket (AF_INET, SOCK_RAW , IPPROTO_TCP);
}

void XmasScan(portscanner * p){
	printf("Scanning %s using XMAS Scan\n", p->host_name);
	printf("Range of ports = %d --> %d \n\n", p->min_port, p->max_port);
	PortScan(p->min_port, p->max_port, p->host_name, 3);
	/* CREATING THE RAW SOCKET */
	//int s = socket (AF_INET, SOCK_RAW , IPPROTO_TCP);
}






int main(int argc, char *argv[]) {
	

	portscanner * p = newPortScanner();
	getOptions(argc, argv, p);
	switch(p->method){
		case 0: printf("I will perform a TCP scan\n"); TCPScan(p); break; 
		case 1: printf("I will perform a SYN scan\n"); SYNScan(p); break;
		case 2: printf("I will perform an NULL scan\n"); NullScan(p); break;
		case 3: printf("I will perform an FIN scan\n"); FinScan(p); break;
		case 4: printf("I will perform an XMAS scan\n"); XmasScan(p); break;
		default: printf("Method not recognized. Goodbye."); return EXIT_FAILURE;
	}
	
	
	/* free allocated memory */
	destroyPortScanner(p);
	return EXIT_SUCCESS;
}
