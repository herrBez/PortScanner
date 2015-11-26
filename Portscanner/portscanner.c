/*
 * client.c
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

void parse(char *url, char *parsed[2]);
char *createRequest(char *pfad, char *hostname);

int main(int argc, char *argv[]) {
	if (argc != 2) {
		fprintf(stderr, "Usage: %s [url]", argv[0]);
		exit(EXIT_FAILURE);
	}
	char *url = argv[1];
	char *relativePath;
	char *request;
	char buffer[1024];
    struct sockaddr_in server;
	int mysocket;
	struct hostent *hostname;

	mysocket = socket(AF_INET, SOCK_STREAM, 0);

    memset(&server, 0, sizeof (server));

    hostname = gethostbyname(url);



    memcpy( (char *)&server.sin_addr, hostname->h_addr_list[0], hostname->h_length);
    server.sin_family = AF_INET;
    
    
    for(int i=0; i<65536; i++){
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
