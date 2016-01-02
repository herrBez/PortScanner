/**
 * TCP Port Scanner with raw sockets in c
 * Available scan methods:
 * Syn, Null, Fin, Xmas
*/
 
#include<stdio.h> 
#include<string.h> 
#include<stdlib.h> 
#include<sys/socket.h>
#include<errno.h> 
#include<netdb.h> 
#include<arpa/inet.h>
#include<netinet/tcp.h>   
#include<netinet/ip.h>    
 
void * receive_ack( void *ptr );
int receive_packet(int s, int port, int method);
unsigned short csum(unsigned short * , int );
char * hostname_to_ip(char * );
int get_local_ip (char *);
void PortScan (int startPort, int endPort, char* target, int method);
void set_tcp_header(struct tcphdr *tcph , int fin, int syn, int rst, int psh, int ack, int urg);



 
struct pseudo_header    //needed for checksum calculation
{
    unsigned int source_address;
    unsigned int dest_address;
    unsigned char placeholder;
    unsigned char protocol;
    unsigned short tcp_length;
     
    struct tcphdr tcp;
};
 

void send_package(int port,  struct tcphdr *tcph, struct pseudo_header psh,  struct sockaddr_in  dest, int s, char* datagram, char * source_ip);

 
