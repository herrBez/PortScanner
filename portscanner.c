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



int main(int argc, char *argv[]) {
	if (argc != 2) {
		fprintf(stderr, "Usage: %s [url]\n", argv[0]);
		exit(EXIT_FAILURE);
	}	
	int i = 0;
	char *url = argv[1];
    struct sockaddr_in server;
	int mysocket;
	struct hostent *hostname;

	mysocket = socket(AF_INET, SOCK_STREAM, 0);

    memset(&server, 0, sizeof (server));

    hostname = gethostbyname(url);



    memcpy( (char *)&server.sin_addr, hostname->h_addr_list[0], hostname->h_length);
    server.sin_family = AF_INET;
    
    
    for(i=0; i<0xFFFF; i++){
		server.sin_port = htons(i);
		if(connect(mysocket, (struct sockaddr *)&server, sizeof(server))<0){
			//perror("connect");
			//return EXIT_FAILURE;
		}
		else{
			printf("Port %d is open.\n", i);
			close(mysocket);
			mysocket = socket(AF_INET, SOCK_STREAM, 0);
			sleep(1);
		}
	
	}


	return EXIT_SUCCESS;
}
