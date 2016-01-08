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
 
struct in_addr dest_ip;

void send_package(int port,  struct tcphdr *tcph, struct pseudo_header psh,  struct sockaddr_in  dest, int s, char* datagram, char * source_ip);

/*
int main(int argc, char *argv[])
{
    char *target = argv[1];
     
    if(argc < 2)
    {
        printf("Please specify a hostname \n");
        exit(1);
    }
     
     PortScan(1, 6000, target, 1);
          
    return 0;
}*/



/**
 * Function to scan ports
 * @param method 0=syn_scan, 1=null_scan, 2=fin_scan, 3=xmas_scan
 */
void PortScan (int startPort, int endPort, char* target, int method){
	
	 //Create a raw socket

    int s = socket (AF_INET, SOCK_RAW , IPPROTO_TCP);
    if(s < 0)
    {
        printf ("Error creating socket. Error number : %d . Error message : %s \n" , errno , strerror(errno));
        exit(0);
    }
    else
    {
        printf("Socket created.\n");
    }
    
    
    //Datagram to represent the packet
    char datagram[4096];    
     
    //IP header
    struct iphdr *iph = (struct iphdr *) datagram;
     
    //TCP header
    struct tcphdr *tcph = (struct tcphdr *) (datagram + sizeof (struct ip));
     
    struct sockaddr_in  dest;
    struct pseudo_header psh;
    
    
    if( inet_addr( target ) != -1)
    {
        dest_ip.s_addr = inet_addr( target );
    }
    else
    {
        char *ip = hostname_to_ip(target);
        if(ip != NULL)
        {
            //printf("%s resolved to %s \n" , target , ip);
            //Convert domain name to IP
            dest_ip.s_addr = inet_addr( hostname_to_ip(target) );
        }
        else
        {
            printf("Unable to resolve hostname : %s" , target);
            exit(1);
        }
    }
     
    char source_ip[20];
    get_local_ip( source_ip );
     
    //printf("Local source IP is %s \n" , source_ip);
     
    memset (datagram, 0, 4096); /* zero out the buffer */
     
    //Fill in the IP Header
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = sizeof (struct ip) + sizeof (struct tcphdr);
    iph->id = htons (54321); //Id of this packet
    iph->frag_off = htons(16384);
    iph->ttl = 64;
    iph->protocol = IPPROTO_TCP;
    iph->check = 0;      //Set to 0 before calculating checksum
    iph->saddr = inet_addr ( source_ip );    //Spoof the source ip address
    iph->daddr = dest_ip.s_addr;
     
    iph->check = csum ((unsigned short *) datagram, iph->tot_len >> 1);
    
    //Fill in the TCP Header depending on scan method
    if(method == 0)
		set_tcp_header(tcph , 0, 1, 0, 0, 0, 0);
	else if (method == 1)
		set_tcp_header(tcph , 0, 0, 0, 0, 0, 0);
	else if (method == 2)
		set_tcp_header(tcph , 1, 0, 0, 0, 0, 0);
	else 
		set_tcp_header(tcph, 1, 0, 0, 1, 0, 1);

     

    //IP_HDRINCL to tell the kernel that headers are included in the packet
    int one = 1;
    const int *val = &one;
     
    if (setsockopt (s, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0)
    {
        printf ("Error setting IP_HDRINCL. Error number : %d . Error message : %s \n" , errno , strerror(errno));
        exit(0);
    }
    
    
    //printf("Starting to send syn packets\n");
     
    int port;
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = dest_ip.s_addr;
    

    for(port = startPort ; port <=endPort ;)
    {
		send_package(port, tcph, psh, dest, s, datagram, source_ip);
		
		int result = receive_packet(s, port, method);
		while (result < 0){
			result = receive_packet(s, port, method);

		 }
		 port++; 
	 }
	
}


void set_tcp_header(struct tcphdr *tcph , int fin, int syn, int rst, int psh, int ack, int urg){
	int source_port = 43591;
	tcph->source = htons ( source_port );
    tcph->seq = htonl(1105024978);
    tcph->ack_seq = 0;
    tcph->doff = sizeof(struct tcphdr) / 4;     
    tcph->fin=fin;
    tcph->syn=syn;
    tcph->rst=rst;
    tcph->psh=psh;
    tcph->ack=ack;
    tcph->urg=urg;
    tcph->window = htons ( 14600 );  // maximum allowed window size
    tcph->urg_ptr = 0;
}


void send_package(int port,  struct tcphdr *tcph, struct pseudo_header psh,  struct sockaddr_in  dest, int s, char* datagram, char * source_ip){
	tcph->dest = htons ( port );	 
	psh.source_address = inet_addr( source_ip );
	psh.dest_address = dest.sin_addr.s_addr;
	psh.placeholder = 0;
	psh.protocol = IPPROTO_TCP;
	psh.tcp_length = htons( sizeof(struct tcphdr) );
	 
	memcpy(&psh.tcp , tcph , sizeof (struct tcphdr));
	 
	tcph->check = csum( (unsigned short*) &psh , sizeof (struct pseudo_header));
	 
	//Send the packet
	if ( sendto (s, datagram , sizeof(struct iphdr) + sizeof(struct tcphdr) , 0 , (struct sockaddr *) &dest, sizeof (dest)) < 0)
	{
		//printf ("Error sending syn packet. Error number : %d . Error message : %s \n" , errno , strerror(errno));
		perror("Error sending packet: ");
		exit(0);
	}
	}
	
 
/**
 * Function to receive packets and afterwards process their contents.
 * 
 * Return Value:
 * 0 if no packet can be received (timeout)
 * -1 if wrong packet received (wrong source port or ip)
 * port if corrrect packet received
 */
int receive_packet(int s, int port, int method)
{
		unsigned char *buffer = (unsigned char *)malloc(65536); 
		struct timeval tv;
		fd_set fds;
		struct sockaddr saddr;

        int saddr_size, data_size;
        saddr_size = sizeof saddr;
	
		FD_ZERO(&fds);
		FD_SET(s, &fds);
		tv.tv_sec = 1;
		tv.tv_usec = 0;
		select(s+ 1, &fds, NULL, NULL, &tv);

		
		if (FD_ISSET(s, &fds))
		{
			data_size = recvfrom(s , buffer , 65536 , 0 , &saddr , &saddr_size);
			//Get the IP Header part of this packet
			struct iphdr *iph = (struct iphdr*)buffer;
			struct sockaddr_in source,dest;
			unsigned short iphdrlen;
     
			if(iph->protocol == 6)
			{	
				iphdrlen = iph->ihl*4;

				struct tcphdr *tcph=(struct tcphdr*)(buffer + iphdrlen);
				 
				memset(&source, 0, sizeof(source));
				source.sin_addr.s_addr = iph->saddr;
		 
				memset(&dest, 0, sizeof(dest));
				dest.sin_addr.s_addr = iph->daddr;
				
				//check if received packet is answer to the sent packet
				if(source.sin_addr.s_addr == dest_ip.s_addr && port == ntohs(tcph->source))
				{
					 if(method == 0){
						 if(tcph->syn == 1 && tcph->ack == 1){
							 printf("Port: %d is open\n", port);
						 }
					 }
					return port;
				}else{
					return -1;
				}
			}else{
				return -1;
			}
		}
		else{
			if(method !=0){
				printf("Port: %d is open\n", port);
			}
			if(method ==0){
				printf("Received timeout, port %d coulb be filtered by firewal", port);
			}
			return 0;
		}
}
 
/*
 Checksums - IP and TCP
 */
unsigned short csum(unsigned short *ptr,int nbytes) 
{
    register long sum;
    unsigned short oddbyte;
    register short answer;
 
    sum=0;
    while(nbytes>1) {
        sum+=*ptr++;
        nbytes-=2;
    }
    if(nbytes==1) {
        oddbyte=0;
        *((u_char*)&oddbyte)=*(u_char*)ptr;
        sum+=oddbyte;
    }
 
    sum = (sum>>16)+(sum & 0xffff);
    sum = sum + (sum>>16);
    answer=(short)~sum;
     
    return(answer);
}
 
/*
    Get ip from domain name
 */
char* hostname_to_ip(char * hostname)
{
    struct hostent *he;
    struct in_addr **addr_list;
    int i;
         
    if ( (he = gethostbyname( hostname ) ) == NULL) 
    {
        // get the host info
        herror("gethostbyname");
        return NULL;
    }
 
    addr_list = (struct in_addr **) he->h_addr_list;
     
    for(i = 0; addr_list[i] != NULL; i++) 
    {
        //Return the first one;
        return inet_ntoa(*addr_list[i]) ;
    }
     
    return NULL;
}
 
/*
 Get source IP of system , like 192.168.0.6 or 192.168.1.2
 */
 
int get_local_ip ( char * buffer)
{
    int sock = socket ( AF_INET, SOCK_DGRAM, 0);
 
    struct sockaddr_in dst;
    dst.sin_family = AF_INET;

 
    int err = connect( sock , (const struct sockaddr*) &dst , sizeof(dst) );
    if(err<0){
		return err;
	}

	socklen_t alen = sizeof(dst);

 
   // struct sockaddr_in name;
    err = getsockname(sock, (struct sockaddr*) &dst, &alen);
    if(err<0){
		return err;
	}
 
    const char *p = inet_ntop(AF_INET, &dst.sin_addr, buffer, 100);
 
	printf("Source %s\n", inet_ntoa(dst.sin_addr));
	buffer = inet_ntoa(dst.sin_addr);
    close(sock);
    return 1;
}
