/*
 * portscanner.c
 * Main File of the project portscanner at the university of Innsbruck
 * Course: Angewandte Informationssicherheit
 *
 * 
 */

//#include <arpa/inet.h>
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
}portscanner;

void printHelp(char * program_name){
	printf("================================\n");
	printf("=== Portscanner help message ===\n");
	printf("================================\n");
	printf("Usage: %s url [options]\n", program_name);
	printf("Options:\n\n");
	printf("\t -h \t print this help and exit\n");
	printf("\t -p \t specify a port range in form min-max (Defualt 1-65535)\n");
	printf("\nAuthors: Simon Targa, Mirko Bez\n");
	exit(EXIT_SUCCESS);
}

void parsePort(char * ports, portscanner * p){
	printf("Parsing ports: %s", ports);
	char * tmp;
	tmp = strtok(ports, "-");
	if(tmp == NULL)
		perror("Parse Port");
	p->min_port = strtol(tmp, NULL, 0);
	tmp = strtok(NULL, "-");
	p->max_port = strtol(tmp, NULL, 0);
}

void getOptions(int argc, char * argv[], portscanner * p){
	int opt;
	while((opt = getopt(argc, argv, "ph")) != -1) {
		switch(opt){
			case 'p': printf("Option p set Port Range = %s!!\n", argv[optind++]); 
			parsePort(argv[optind-1], p); break;
			case 'h': printHelp(argv[0]); break;
		}
	}
}

portscanner * newPortScanner(){
	portscanner * p = malloc(sizeof(portscanner));
	p->min_port = 1;
	p->max_port = 65535;
	return p;
}

void destroyPortScanner(portscanner * p){
	free(p);
}

int main(int argc, char *argv[]) {
	if (argc < 2) 
		printHelp(argv[0]);
	char *url = argv[1];

	portscanner * p = newPortScanner();
	getOptions(argc, argv, p);
	
	printf("Range of ports = %d --> %d \n\n", p->min_port, p->max_port);

	
	int i = 0;
    struct sockaddr_in server;
	int mysocket;
	struct hostent *hostname;

	mysocket = socket(AF_INET, SOCK_STREAM, 0);

    memset(&server, 0, sizeof (server));
	/** N.B. GETHOSTBYNAME IS OBSOLETE */
    hostname = gethostbyname(url);


    memcpy( (char *)&server.sin_addr, hostname->h_addr_list[0], hostname->h_length);
    server.sin_family = AF_INET;
    
    int counter = 0;
    for(i = p->min_port; i <= p->max_port; i++){
		server.sin_port = htons(i);
		if(connect(mysocket, (struct sockaddr *)&server, sizeof(server))<0){
			//perror("connect");
			//return EXIT_FAILURE;
		}
		else{
			printf("TCP - Port %d is open.\n", i);
			close(mysocket);
			mysocket = socket(AF_INET, SOCK_STREAM, 0);
			counter++;
			sleep(1);
		}
	
	}
	
	/* Printing results */
	printf("\n%d Ports in range [%d,%d] are open on Host '%s'\n", counter, p->min_port, p->max_port, url);

	/* free allocated memory */
	destroyPortScanner(p);
	return EXIT_SUCCESS;
}
