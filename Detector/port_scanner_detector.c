/**************************************************************************************************
 * Port Scan Detector. 
 * 
 * This program should recognize a (TCP) port scan.
 * 
 * 
 * 
 * 
 * 
 * Important note: In order to use this program you have to install libcap-dev (in Debian based Linux-Distros)
 * 
 * Important sources: 
 * PCAP FILTER RULES : http://www.tcpdump.org/manpages/pcap-filter.7.html
 * PCAP CODE EXAMPLE (BASIS OF THIS IMPLEMENTATION!!): http://www.tcpdump.org/pcap.html
 * PORT SCAN DETECTION FUNCTIONALITY : https://www.sophos.com/it-it/support/knowledgebase/115153.aspx
 * 
 *****************************************************************************************************/

#include "./include/important_header.h"

static int counter = 0;

/* Head of the linked list containing the information about the ip-adresses who potentially are trying to port scan us */				
node_t * head;	
/* packet counter */						
static int count = 1;  
/* If is set to 1 the scanned tcp ports (and the number of times) are also saved! */                
static int _get_all_info = 1;

pcap_t * handle;	




/*
 * dissect/print packet
 */
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
	/* declare pointers to packet headers */
	const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
	const struct sniff_ip *ip;              /* The IP header */
	const struct sniff_tcp *tcp;            /* The TCP header */
	const char *payload;                    /* Packet payload */
	
	/* Variables */
	int size_ip;
	int size_tcp;
	
	printf("\nPacket number %d:\n", count++);
	
	/* define ethernet header */
	ethernet = (struct sniff_ethernet*)(packet);
	
	/* define/compute ip header offset */
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
		printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}

	/*
	 * IMPORTANT: from the inet_ntoa() MAN PAGE:
	 * 
	 * The inet_ntoa() function converts the Internet host address  in,  given
     * in  network  byte  order,  to a string in IPv4 dotted-decimal notation.
     * The string is returned in a statically allocated buffer,  which  subse‐
     * quent calls will overwrite.
     * 
     *  ==> IT IS NECESSARY TO COPY THE VALUE
	 */ 
	char * tmp = inet_ntoa(ip->ip_src);
	char * actual_adress = malloc((strlen(tmp)+1) * sizeof(char));
	strcpy(actual_adress, tmp);
	
	
	node_t * actual_node;
	
	if(head == NULL){
		printf("Adding the first element %s \n", actual_adress);
		head = newNode(actual_adress);
	}
	else if(!contains(head, actual_adress)){
		push(head, actual_adress);
	}	
	
	actual_node = contains_node(head, actual_adress);
	//printf("ACTUAL NODE:"); printNode(actual_node);

	/* print source and destination IP addresses */
	printf("       From: %s\n", actual_adress);
	printf("         To: %s\n", inet_ntoa(ip->ip_dst));
	
	free(actual_adress);
	
	
	/* determine protocol */	
	switch(ip->ip_p) {
		case IPPROTO_TCP:
			actual_node->tcp++;
			
			printf("   Protocol: TCP\n");
			break;
		case IPPROTO_UDP:
			actual_node->udp++;
			printf("   Protocol: UDP\n");
			return;
		case IPPROTO_ICMP:
			actual_node->icmp++;
			printf("   Protocol: ICMP\n");
			return;
		case IPPROTO_IP:
			actual_node->ip++;
			printf("   Protocol: IP\n");
			return;
		default:
			printf("   Protocol: unknown\n");
			actual_node->unknown++;
			return;
	}
	
	/*
	 *  The packet is securely tcp!
	 */
	
	/* define/compute tcp header offset */
	tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
	size_tcp = TH_OFF(tcp)*4;
	if (size_tcp < 20) {
		printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
		return;
	}
	int dst_port = ntohs(tcp->th_dport);
	
	printf("   Src port: %d\n", ntohs(tcp->th_sport));
	printf("   Dst port: %d\n", dst_port);
	
	
	
	
	if(_get_all_info){
		if(actual_node->port_list == NULL){
			actual_node->port_list = new_my_port(dst_port);
		} else {
			my_port * actual_port = contains_my_port(actual_node->port_list, dst_port);
			if(actual_port == NULL){
				push_my_port(actual_node->port_list, dst_port);
			} else {
				actual_port->times++;
			}
		
		}	
	}	

	
	/* ADDING THE SCORE ACCORDINGLY TO 	https://www.sophos.com/it-it/support/knowledgebase/115153.aspx */
	if(dst_port <= 0)
		fprintf(stderr, "ERROR PORT NEGATIVE\n");
	else if(dst_port > 65536)
		fprintf(stderr, "ERROR PORT TOO BIG\n");
	else if(dst_port == 11 || dst_port == 12 || dst_port == 13 || dst_port == 2000)
		actual_node->score += 10;
	else if(dst_port < 1024)
		actual_node->score += 3;
	else if(dst_port >= 1024)
		actual_node->score += 1;
	
	/* IF PAYLOAD MATTERS -> PLEASE UNCOMMENT THE FOLLOWING LINES!
	int size_payload;
	//define/compute tcp payload (segment) offset 
	payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
	
	// compute tcp payload (segment) size 
	size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
	
	
	 // Print payload data; it might be binary, so don't just
	 // treat it as a string.
	 
	//printf("   Payload (%d bytes):\n", size_payload);

	*/

return;
}

/**
 * Function called when a Ctrl-C is received:
 * It breaks the pcap_loop
 */
void intHandler(int d){
	printf("\n\n\n\n");
	printf("**************************************\n");
	printf("* Ctrl-C caught. Breaking the loop...*\n");
	printf("**************************************\n");
	pcap_breakloop(handle);
}



/* https://www.sophos.com/en-us/support/knowledgebase/115153.aspx */
int main(int argc, char * argv[]){

	/* Variable declaration */
	char *dev = NULL;								/* capture device name */
	char errbuf[PCAP_ERRBUF_SIZE];					/* error buffer */
	char filter_exp[] = "dst host 192.168.1.3"; 	/* filter expression */
	struct bpf_program fp;							/* compiled filter program (expression) */
	bpf_u_int32 mask;								/* subnet mask */
	bpf_u_int32 net;								/* ip */
	int num_packets = -1;							/* number of packets to capture */


	/* check for capture device name on command-line */
	if (argc == 2) {
		dev = argv[1];
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
	handle = pcap_open_live(dev, SNAP_LEN, NON_PROMISCUOUS, 1000, errbuf);
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
	
	/* Installing a signal handler for ctrl-c that breaks the pcap_loop function*/
	signal(SIGINT, intHandler);
	
	/* Initializing the list of hosts that are trying to scan the target given in the rule (filter_exp) */
	head = NULL;
	
	/* now we can set our callback function */
	pcap_loop(handle, num_packets, got_packet, NULL);
	print_list(head);
	
	/* cleanup */
	free_list(head);
	pcap_freecode(&fp);
	pcap_close(handle);

	printf("\nCapture complete.\n");
	return EXIT_SUCCESS;
}
