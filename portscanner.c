/*
 * portscanner.c
 * Main File of the project portscanner at the university of Innsbruck
 * Course: Angewandte Informationssicherheit
 *
 * 
 */

//#include <arpa/inet.h>
#include "portscanner.h"




void printHelp(char * program_name){
	printf("================================\n");
	printf("=== Portscanner help message ===\n");
	printf("================================\n");
	printf("Usage: %s [options]\n", program_name);
	printf("Options:\n\n");
	printf("\t -h \t print this help and exit\n");
	printf("\t -p \t specify a port range in form min-max (Defualt 1-65535)\n");
	printf("\t -u \t specify a url to scan (Default localhost)\n");
	printf("\t -v \t verbose output");
	printf("\n\nAuthors: Simon Targa, Mirko Bez\n");
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
	while((opt = getopt(argc, argv, "phuv")) != -1) {
		switch(opt){
			case 'p': parsePort(argv[optind], p); break;
			case 'h': printHelp(argv[0]); break;
			case 'u': free(p->host_name); p->host_name = strdup(argv[optind]); break;
			case 'v': p->verbose = 1;
		}
	}
}

portscanner * newPortScanner(){
	portscanner * p = malloc(sizeof(portscanner));
	p->min_port = 1;
	p->max_port = 65535;
	p->host_name = strdup("localhost");
	p->verbose = 0;
	p->counter = 0;
	return p;
}



int main(int argc, char *argv[]) {
	

	portscanner * p = newPortScanner();
	getOptions(argc, argv, p);
	
	printf("Scanning %s \n", p->host_name);
	printf("Range of ports = %d --> %d \n\n", p->min_port, p->max_port);

	
	int i = 0;
    struct sockaddr_in server;
	int mysocket;
	struct hostent *hostname;

	mysocket = socket(AF_INET, SOCK_STREAM, 0);

    memset(&server, 0, sizeof (server));
	/** N.B. GETHOSTBYNAME IS OBSOLETE */
    hostname = gethostbyname(p->host_name);


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

	/* free allocated memory */
	destroyPortScanner(p);
	return EXIT_SUCCESS;
}
