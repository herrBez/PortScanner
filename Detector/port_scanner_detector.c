/**************************************************************************************************
 * Port Scan Detector. This program should recognize a port scan.
 * 
 * 
 * 
 * 
 * 
 * Important note: In order to use this program you have to install libcap-dev (in Debian based Linux-Distros)
 * 
 * Important sources: 
 * PCAP FILTER RULES : http://www.tcpdump.org/manpages/pcap-filter.7.html
 * PCAP CODE EXAMPLE : http://www.tcpdump.org/pcap.html
 * PORT SCAN DETECTION FUNCTIONALITY : https://www.sophos.com/it-it/support/knowledgebase/115153.aspx
 * 
 *****************************************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <pcap/pcap.h>
#include <string.h>
#include <stdbool.h>

#define SNAP_LEN 1518
#define PORT_SCAN_SCORE 21
static int counter = 0;
#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

//Capture ctrl-c
#include <signal.h>

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

/* Ethernet header */
struct sniff_ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        u_char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};

typedef struct node {
  int score;
  char * ip_src;
  struct node *next;
}node_t;

void printNode(node_t * n){
	printf("[Score = %d][IP = %s]\n", n->score, n->ip_src);
}

node_t * root;

node_t * contains_node(node_t * head, char * ip_src){
	bool is_contained = false;
	node_t * current = head;
	while(current != NULL){
		int res = strcmp(current->ip_src, ip_src);
		if(res == 0){
			printf("%s::%s\n", current->ip_src, ip_src);
			is_contained = true;
			break;
		} else {
			printf("%s--%s\n", current->ip_src, ip_src);
			
		}
		if(current->next == NULL)
			break;
		current = current->next;
	}
	if(is_contained){
		return current;
	} else {
		return NULL;
	}
}

bool contains(node_t * head, char * ip_src){
	bool is_contained = false;
	node_t * current = head;
	while(current != NULL){
		int res = strcmp(current->ip_src, ip_src);
		if(res == 0){
			printf("%s::%s\n", current->ip_src, ip_src);
			is_contained = true;
			break;
		} else {
			printf("%s--%s\n", current->ip_src, ip_src);
			
		}
		if(current->next == NULL)
			break;
		current = current->next;
	}
	return is_contained;
}


void push(node_t * head, char * ip_src) {
    node_t * current = head;
    while (current->next != NULL) {
        current = current->next;
    }

    /* now we can add a new variable */
    current->next = malloc(sizeof(node_t));
    current->next->score = 0;
    current->next->ip_src = malloc(sizeof(char) * (strlen(ip_src)+1));
    strcpy(current->next->ip_src,ip_src);
    current->next->next = NULL;
}
	static int count = 1;                   /* packet counter */

/*
 * dissect/print packet
 */
void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	
	/* declare pointers to packet headers */
	const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
	const struct sniff_ip *ip;              /* The IP header */
	const struct sniff_tcp *tcp;            /* The TCP header */
	const char *payload;                    /* Packet payload */

	int size_ip;
	int size_tcp;
	int size_payload;
	
	printf("\nPacket number %d:\n", count);
	count++;
	
	/* define ethernet header */
	ethernet = (struct sniff_ethernet*)(packet);
	
	/* define/compute ip header offset */
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
		printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}
	
	
	//IMPORTANT: inet_ntoa MAN PAGE:
	/*  The inet_ntoa() function converts the Internet host address  in,  given
       in  network  byte  order,  to a string in IPv4 dotted-decimal notation.
       The string is returned in a statically allocated buffer,  which  subse‐
       quent calls will overwrite.
       ==> IT IS NECESSARY TO COPY THE VALUE
	*/
	char * actual_adress = malloc(sizeof(inet_ntoa(ip->ip_src)));
	strcpy(actual_adress, inet_ntoa(ip->ip_src));
	
	node_t * actual_node;
	
	if(root == NULL){
		printf("Adding the first element %s \n", actual_adress);
		root = calloc(1,sizeof(node_t));
		root->ip_src = malloc(sizeof(char) * (strlen(actual_adress) + 1));
		strcpy(root->ip_src, actual_adress);
		root->score = 0;
		root->next = NULL;
		actual_node = root;
	}
	
	else if(contains(root, actual_adress)){
		printf("IS ALREADY CONTAINED\n");
	} else {
		printf("PUSH %s\n", actual_adress);
		push(root, actual_adress);
	}	
	
	actual_node = contains_node(root, actual_adress);
	printf("ACTUAL NODE:");
	printNode(actual_node);

	/* print source and destination IP addresses */
	printf("       From: %s\n", actual_adress);
	printf("         To: %s\n", inet_ntoa(ip->ip_dst));
	
	free(actual_adress);
	
	
	/* determine protocol */	
	switch(ip->ip_p) {
		case IPPROTO_TCP:
			printf("   Protocol: TCP\n");
			break;
		case IPPROTO_UDP:
			printf("   Protocol: UDP\n");
			return;
		case IPPROTO_ICMP:
			printf("   Protocol: ICMP\n");
			return;
		case IPPROTO_IP:
			printf("   Protocol: IP\n");
			return;
		default:
			printf("   Protocol: unknown\n");
			return;
	}
	
	/*
	 *  OK, this packet is TCP.
	 */
	
	/* define/compute tcp header offset */
	tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
	size_tcp = TH_OFF(tcp)*4;
	if (size_tcp < 20) {
		printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
		return;
	}
	
	printf("   Src port: %d\n", ntohs(tcp->th_sport));
	printf("   Dst port: %d\n", ntohs(tcp->th_dport));
	
	int dst_port = ntohs(tcp->th_dport);
	
	if(dst_port <= 0){
		printf("ERROR");
	} 
	else if(dst_port == 11 || dst_port == 12 || dst_port == 13 || dst_port == 2000){
		actual_node->score += 10;
	}
	else if(dst_port < 1024){
		actual_node->score += 3;
	}
	else if(dst_port >= 1024){
		actual_node->score += 1;
	}
	
	
	/* define/compute tcp payload (segment) offset */
	payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
	
	/* compute tcp payload (segment) size */
	size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
	
	/*
	 * Print payload data; it might be binary, so don't just
	 * treat it as a string.
	 */
	printf("   Payload (%d bytes):\n", size_payload);

	if (size_payload > 0) {
		//print_payload(payload, size_payload);
	}

return;
}


pcap_t *handle;		
void intHandler(int d){
	printf("Ctrl-C catched. Breaking the loop...\n");
	pcap_breakloop(handle);
}

void print_list(node_t * head) {
	if(head == NULL){
		printf("\n<The List is empty>\n");
		return;
	}
    node_t * current = head;

    while (current != NULL) {
		if(current->score > PORT_SCAN_SCORE){
			printf("\n***Port Scan from adress %s detected***\n", current->ip_src);
		} else {
			printNode(current);
		}
        current = current->next;
    }
}

free_list(node_t * head){
	node_t * curr;
	while ((curr = head) != NULL) { // set curr to head, stop if list empty.
		head = head->next;          // advance head to next element.
		free (curr->ip_src);
		free (curr);                // delete saved pointer.
	}
}


/* https://www.sophos.com/en-us/support/knowledgebase/115153.aspx */
int main(int argc, char * argv[]){

	char *dev = NULL;			/* capture device name */
	char errbuf[PCAP_ERRBUF_SIZE];		/* error buffer */
			/* packet capture handle */

	//dst host 192.168.1.3

	char filter_exp[] = "dst host 192.168.1.3 && dst portrange 1-100";		/* filter expression */
	struct bpf_program fp;			/* compiled filter program (expression) */
	bpf_u_int32 mask;			/* subnet mask */
	bpf_u_int32 net;			/* ip */
	int num_packets = -1;			/* number of packets to capture */


	/* check for capture device name on command-line */
	if (argc == 2) {
		dev = argv[1];
	}
	else if (argc > 2) {
		fprintf(stderr, "error: unrecognized command-line options\n\n");
		exit(EXIT_FAILURE);
	}
	else {
		/* find a capture device if not specified on command-line */
		dev = pcap_lookupdev(errbuf);
		if (dev == NULL) {
			fprintf(stderr, "Couldn't find default device: %s\n",
			    errbuf);
			exit(EXIT_FAILURE);
		}
	}
	
	/* get network number and mask associated with capture device */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
		    dev, errbuf);
		net = 0;
		mask = 0;
	}

	/* print capture info */
	printf("Device: %s\n", dev);
	printf("Number of packets: %d\n", num_packets);
	printf("Filter expression: %s\n", filter_exp);

	/* open capture device */
	handle = pcap_open_live(dev, SNAP_LEN, 0, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		exit(EXIT_FAILURE);
	}

	/* make sure we're capturing on an Ethernet device [2] */
	if (pcap_datalink(handle) != DLT_EN10MB) {
		fprintf(stderr, "%s is not an Ethernet\n", dev);
		exit(EXIT_FAILURE);
	}

	/* compile the filter expression */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n",
		    filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	/* apply the compiled filter */
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n",
		    filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}
	
	
	signal(SIGINT, intHandler);
	root = NULL;
	
	/* now we can set our callback function */
	pcap_loop(handle, -1, got_packet, NULL);
	//printf("\n\n\nLEN %d\n\n\n\n", len(root));
	print_list(root);
	
	/* cleanup */
	free_list(root);
	pcap_freecode(&fp);
	pcap_close(handle);

	printf("\nCapture complete.\n");
	return EXIT_SUCCESS;
}
