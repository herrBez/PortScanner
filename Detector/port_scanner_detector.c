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
#include <getopt.h>


/* Head of the linked list containing the information about the ip-adresses who potentially are trying to port scan us */				
node_t * head;	
/* packet counter */						
static int count = 1;  
/* If is set to 1 the scanned tcp ports (and the number of times) are also saved! */                
static bool _get_all_info = false;
/* struct used in order to capture the packets using the library pcap */
pcap_t * handle;	
/* contains the fixed time interval 300 ms */
struct timespec _my_time; 
/* say to a thred to stop */
bool break_thread = false;





void my_get_options(int argc, char * argv[], char **dev, int * num_packets, char ** dst_ip, bool * verbose, char ** output_file_name){
	int opt;
	int option_index = 0;
	
	struct option opts[] = {
		{"help", no_argument, NULL, 'h'},
		{"save-the-ports", no_argument, NULL, 's'},
		{"device", required_argument, NULL, 'd'},
		{"max-num-of-packets", required_argument, NULL, 'm'},
		{"verbose", no_argument, NULL, 'v'},
		{"dst-ip", required_argument, NULL, 'i'},
		{"log-file", required_argument, NULL, 'l'},
		{0,0,0,0}, //In order to recognize the end of the array
	};
	
	while((opt = getopt_long(argc, argv, "hsd:m:i:vl:", opts, &option_index)) != -1){
		switch(opt){
			case 'h': printHelp(argv[0]); 
				break;
			case 's': _get_all_info = true; 
				break;
			case 'd': 
					*dev = strdup(optarg);
					break;
			case 'm': *num_packets = (int) strtol(optarg, NULL, 0); 
				break;
			case 'i': 
					*dst_ip = strdup(optarg); 
					break;
			case 'v': 
					*verbose = true;
					break;
			case 'l':
					*output_file_name = strdup(optarg); printf("OUTPUT FILE NAME %s\n", *output_file_name);
					break;  
		}
	}
	
}





/**
 * Function called when a Ctrl-C is received:
 * It breaks the pcap_loop
 */
void my_sigint_handler(int d){
	printf("\n\n\n\n");
	printf("***************************************\n");
	printf("* Ctrl-C caught. Breaking the loop... *\n");
	printf("***************************************\n\n");
	pcap_breakloop(handle);
	break_thread = true;
}

int get_score(int dst_port){
	if(dst_port <= 0)
		fprintf(stderr, "ERROR PORT NEGATIVE\n");
	else if(dst_port > 65536)
		fprintf(stderr, "ERROR PORT TOO BIG\n");
	else if(dst_port == 11 || dst_port == 12 || dst_port == 13 || dst_port == 2000){
		return 10;
	}
	else if(dst_port < 1024){
		return 3;
	}
	else if(dst_port >= 1024){
		return 1;
	}
	return 0;
}

void process_udp(const u_char *packet, const struct sniff_ip *ip, int size_ip, node_t * actual_node){
	const struct sniff_udp *udp;
	int dst_port;
	udp = (struct sniff_udp*)(packet + SIZE_ETHERNET + size_ip);
	dst_port =  ntohs(udp->dst_port);
	printf("UDP DEST PORT %d\n", dst_port);
	int tmp = get_score(dst_port);
	actual_node->udp_actual_score += tmp;
	actual_node->udp_total_score += tmp;
	if(_get_all_info){
		printf("GET ALL INFO UDP\n");
		if(actual_node->udp_port_list == NULL){
			actual_node->udp_port_list = new_my_port(dst_port);
		} else {
			my_port * actual_port = contains_my_port(actual_node->udp_port_list, dst_port);
			if(actual_port == NULL){
				push_my_port(&actual_node->udp_port_list, dst_port);	
			} else {
				actual_port->times++;
			}
		
		}	
	}	
}

void process_tcp(const u_char *packet, const struct sniff_ip *ip, int size_ip, node_t * actual_node){
	int dst_port;
	int size_tcp;
	int size_payload;
	const struct sniff_tcp *tcp;            /* The TCP header */
	/* define/compute tcp header offset */
	tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
	size_tcp = TH_OFF(tcp)*4;
	if (size_tcp < 20) {
		printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
		return;
	}
	dst_port = ntohs(tcp->th_dport);
	
	printf("   TCP Packet type: ");
	int index;
	if(tcp->th_flags == get_syn_scan_flags()){
		index = INDEX_SYN;
		printf("SYN\n");
	} else if(tcp->th_flags == get_ack_scan_flags()){
		index = INDEX_ACK;
		printf("ACK\n");
	} else if(tcp->th_flags == get_null_scan_flags()){
		index = INDEX_NULL;
		printf("NULL\n");
	} else if(tcp->th_flags == get_xmas_scan_flags()){
		index = INDEX_XMAS;
		printf("XMAS\n");
	} else if(tcp->th_flags == get_fin_scan_flags()){
		index = INDEX_FIN;
		printf("FIN\n");
	} else if(tcp->th_flags == get_maimon_scan_flags()){
		index = INDEX_MAIMON;
		printf("MAIMON (FIN | ACK)\n");
	}
	else {
		index = INDEX_UNKNOWN;
		printf("Not known scan type (Flag set to 0x%X := ", tcp->th_flags);
		print_tcp_flags(tcp->th_flags);
		printf(")\n");
	}
	
	actual_node->tcp[index]++;
	
	
	printf("   Src port: %d\n", ntohs(tcp->th_sport));
	printf("   Dst port: %d\n", dst_port);
	
	
	
	
	if(_get_all_info){
		if(actual_node->tcp_port_list == NULL){
			actual_node->tcp_port_list = new_my_port(dst_port);
		} else {
			my_port * actual_port = contains_my_port(actual_node->tcp_port_list, dst_port);
			if(actual_port == NULL){
				push_my_port(&actual_node->tcp_port_list, dst_port);	
			} else {
				actual_port->times++;
			}
		
		}	
	}	

	
	/* ADDING THE SCORE ACCORDINGLY TO 	https://www.sophos.com/it-it/support/knowledgebase/115153.aspx */
	int tmp = get_score(dst_port);
	actual_node->tcp_actual_score[INDEX_TCP] += tmp;
	actual_node->tcp_total_score[INDEX_TCP] += tmp;
	actual_node->tcp_actual_score[index] += tmp;
	actual_node->tcp_total_score[index] += tmp;
	

	/* compute tcp payload (segment) size */
	size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
	printf("   Payload (%d bytes):\n", size_payload);
}



/*
 * dissect/print packet
 */
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
	/* declare pointers to packet headers */
	
	const struct sniff_ip *ip;              /* The IP header */
	
	
	/* Variables */
	char * tmp, * actual_adress;
	node_t * actual_node;
	
	
	printf("\nPacket number %d:\n", count++);
	int size_ip;
	
	
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
	tmp = inet_ntoa(ip->ip_src);
	actual_adress = malloc((strlen(tmp)+1) * sizeof(char));
	strcpy(actual_adress, tmp);
	
	
	
	bool contained = true;
	
	actual_node = contains_node(head, actual_adress);
	
	if(actual_node == NULL){
		push(&head, actual_adress);
		/* start a pthread */
		contained = false;
		actual_node = contains_node(head, actual_adress);
	} else {
		actual_node->end_time = my_now();
	}
	
	if(!contained){
		if(pthread_create(&actual_node->thread, NULL, thread_function, actual_node) != 0){
			perror("Pthread_create()");
			my_sigint_handler(SIGINT);
		}
	}
	/* print source and destination IP addresses */
	printf("       From: %s\n", actual_adress);
	printf("         To: %s\n", inet_ntoa(ip->ip_dst));
	
	free(actual_adress);
	
	
	/* determine protocol */	
	switch(ip->ip_p) {
		case IPPROTO_TCP:
			actual_node->tcp[INDEX_TCP]++;
			printf("   Protocol: TCP\n");
			process_tcp(packet, ip, size_ip, actual_node);
			break;
		case IPPROTO_UDP:
			actual_node->udp++;
			process_udp(packet, ip, size_ip, actual_node);

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
	
	
	return;
}






/* https://www.sophos.com/en-us/support/knowledgebase/115153.aspx */
/**
 * argv[0] program name
 * -i define own ip not optional
 * -d define own device (wlan0, eth0 and so on) optional
 * -m maximum number of packets standard: infinity
 */
int main(int argc, char * argv[]){
	_my_time.tv_sec = 0;
	_my_time.tv_nsec = 300000000; /* Default 300ms */
	
	/* Variable declaration */
	char * dev = NULL;										/* capture device name */
	char errbuf[PCAP_ERRBUF_SIZE];					/* error buffer */
	
	struct bpf_program fp;							/* compiled filter program (expression) */
	bpf_u_int32 mask;								/* subnet mask */
	bpf_u_int32 net;								/* ip */
	int num_packets = -1;							/* number of packets to capture */
	
	char * dst_ip = NULL;
	char * output_file_name = NULL;
	char * filter_expression = calloc(64, sizeof(char));
	bool verbose = false; 
	my_get_options(argc, argv, &dev, &num_packets, &dst_ip, &verbose, &output_file_name);
	
	if(dst_ip == NULL){
		printf("USING LOCALHOST\n");
		dst_ip = strdup("127.0.0.1");
		dev = strdup("lo");
	}
	else {
	/* Not given as parameter */
	if(dev == NULL) {
		dev = calloc(64, sizeof(char));
	
		errbuf[0] = '\0';
	
		/* find a capture device if not specified on command-line */
		strcpy(dev, pcap_lookupdev(errbuf));
		if (strlen(errbuf) > 0) {
			fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
			exit(EXIT_FAILURE);
		}
	}
	}
	sprintf(filter_expression, "dst host %s", dst_ip);
	
	/* get network number and mask associated with capture device */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
		    dev, errbuf);
		net = 0;
		mask = 0;
	}
	
	printInfo(dev, num_packets, filter_expression);

	/* open capture device */
	handle = pcap_open_live(dev, SNAP_LEN, NON_PROMISCUOUS, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		exit(EXIT_FAILURE);
	}

	/* make sure we're capturing on an Ethernet device [2] */
	if (pcap_datalink(handle) != DLT_EN10MB) {
		fprintf(stderr, "%s is not an Ethernet\n", dev);
		fprintf(stderr, "Are you connected to the internet?\n");
		exit(EXIT_FAILURE);
	}

	/* compile the filter expression */
	if (pcap_compile(handle, &fp, filter_expression, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n",
		    filter_expression, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	/* apply the compiled filter */
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n",
		    filter_expression, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}
	
	/* Installing a signal handler for ctrl-c that breaks the pcap_loop function*/
	struct sigaction main_thread_sigaction;
	main_thread_sigaction.sa_handler = my_sigint_handler;
    sigemptyset(&main_thread_sigaction.sa_mask);
    main_thread_sigaction.sa_flags = 0; 
    
   
	if(sigaction(SIGINT, &main_thread_sigaction, NULL) == -1){
		perror("Sigaction()");
	}
	
	
	/* Initializing the list of hosts that are trying to scan the target given in the rule (filter_exp) */
	head = NULL;
	
	printf("***************************************************************************\n");
	printf("Begin scanning at: ");
	print_now();
	printf("***************************************************************************\n");
    
	time_t begin_time = my_now();
	
	/* now we can set our callback function */
	pcap_loop(handle, num_packets, got_packet, NULL);
	break_thread = true;
	/* WAITING ALL THE THREADS TO FINISH */
	node_t * current = head;
	printf("***************************************************************************\n");
	printf("Joining all the threads...");
	

	while(current != NULL){
		pthread_join(current->thread, NULL);
		current = current->next;
	}
	printf(" Done.\n");
	printf("***************************************************************************\n\n");
	printf("***************************************************************************\n");
	printf("End Scanning at: ");
	print_now();
	
	printf("***************************************************************************\n\n");
	
	time_t end_time = my_now();
	double elapsed_time = difftime(end_time, begin_time);
	printf("****************************************\n");
	printf(" TOTAL TIME ELAPSED %.0f seconds\n", elapsed_time);
	printf("****************************************\n\n");
	
	print_list(head);
	
	if(output_file_name != NULL)
		output_file_f(output_file_name, head, begin_time, end_time, elapsed_time, count, _get_all_info, filter_expression, dev);
	
	
	/* cleanup */
	free_list(head);
	pcap_freecode(&fp);
	pcap_close(handle);
	free(dev);
	free(dst_ip);
	free(output_file_name);				
	free(filter_expression);
	printf("\nCapture complete.\n");
	return EXIT_SUCCESS;
}
