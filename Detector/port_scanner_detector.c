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




void printHelp(char * program_name){
	printf("=========================================\n");
	printf("=== Portscanner Detector help message ===\n");
	printf("=========================================\n");
	printf("Usage: %s [options]\n", program_name);
	printf("Options:\n\n");
	printf("\t -h \t print this help and exit\n");
	printf("\t -s \t save all the tcp ports requested from the potential attackers\n");
	printf("\t -d \t specify a device to use (e.g. wlan0, eth0) you can get those devices using the command ifconfig\n");
	printf("\t -v \t verbose output\n");
	printf("\t -i \t destination ip adress\n");
	printf("\t -m \t maximum number of catchable packets after which the program ends\n");
	printf("\nAuthors: Simon Targa, Mirko Bez\n");
	exit(EXIT_SUCCESS);
}


void getOptions(int argc, char * argv[], char ** dev, int * num_packets, char ** dst_ip, bool * verbose){
	int opt;
	while((opt = getopt(argc, argv, "hsdimv")) != -1) {
		switch(opt){
			case 'h': printHelp(argv[0]); break;
			case 's': _get_all_info = true; break; /* Stays for save */
			case 'd': 
				if(optind == argc){
					printf("Option 'd' needs a value!!\n");
					exit(0);
				}
				*dev = strdup(argv[optind]); break; /* stays for device */
			case 'm': *num_packets = (int) strtol(argv[optind], NULL, 0); break;
			case 'i': 
				if(optind == argc){
					printf("Option 'd' needs a value!!\n");
					exit(0);
				}
				*dst_ip = strdup(argv[optind]); printf("DST IP %s\n", *dst_ip);  exit(0); break;
			case 'v': 
				*verbose = true; break;
		}
	}
}





/**
 * Function called when a Ctrl-C is received:
 * It breaks the pcap_loop
 */
void my_sigint_handler(int d){
	printf("\n\n\n\n");
	printf("**************************************\n");
	printf("* Ctrl-C caught. Breaking the loop...*\n");
	printf("**************************************\n");
	pcap_breakloop(handle);
	break_thread = true;
}


struct sigaction main_thread_sigaction;


/*
 * dissect/print packet
 */
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
	/* declare pointers to packet headers */
	
	const struct sniff_ip *ip;              /* The IP header */
	const struct sniff_tcp *tcp;            /* The TCP header */
	
	/* Variables */
	char * tmp, * actual_adress;
	node_t * actual_node;
	
	int size_ip;
	int size_tcp;
	int dst_port;
	int size_payload;
	printf("\nPacket number %d:\n", count++);
	
	
	
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
	dst_port = ntohs(tcp->th_dport);
	
	printf("   Src port: %d\n", ntohs(tcp->th_sport));
	printf("   Dst port: %d\n", dst_port);
	
	
	
	
	if(_get_all_info){
		if(actual_node->port_list == NULL){
			actual_node->port_list = new_my_port(dst_port);
		} else {
			my_port * actual_port = contains_my_port(actual_node->port_list, dst_port);
			if(actual_port == NULL){
				push_my_port(&actual_node->port_list, dst_port);	
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
	else if(dst_port == 11 || dst_port == 12 || dst_port == 13 || dst_port == 2000){
		actual_node->actual_score += 10;
		actual_node->total_score += 10;
	}
	else if(dst_port < 1024){
		actual_node->actual_score += 3;
		actual_node->total_score += 3;
	}
	else if(dst_port >= 1024){
		actual_node->actual_score += 1;
		actual_node->total_score += 1;
	}
	
	
	/* IF THE CONTENT OF PAYLOAD MATTERS -> PLEASE UNCOMMENT THE FOLLOWING LINES! */
	/*const char *payload;                   
	//const struct sniff_ethernet *ethernet;  // The ethernet header [1] 
	// define ethernet header 
	//ethernet = (struct sniff_ethernet*)(packet);
	//int size_payload;
	//define/compute tcp payload (segment) offset 
	//payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);*/
	
	/* compute tcp payload (segment) size */
	size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
	printf("   Payload (%d bytes):\n", size_payload);
	return;
}


void printInfo(char * dev, int num_packets, char * filter_exp){
	printf("   ****************************\n");
	printf("   *** A PORT SCAN DETECTOR ***\n");
	printf("   ****************************\n");

	printf("*****************************************************\n");
	/* print capture info */
	printf("Device: %s\n", dev);
	printf("Number of packets ");

	if(num_packets == -1)
		printf("infinity: i.e. until Ctrl-C occurs\n");
	else 
		printf("%d\n", num_packets);
	printf("Filter expression: %s\n", filter_exp);

	printf("*****************************************************\n\n\n");
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
	char filter_exp[] = "dst host 192.168.1.3"; 	/* filter expression */
	struct bpf_program fp;							/* compiled filter program (expression) */
	bpf_u_int32 mask;								/* subnet mask */
	bpf_u_int32 net;								/* ip */
	int num_packets = -1;							/* number of packets to capture */
	
	char * dst_ip;
	
	bool verbose = false; 
	getOptions(argc, argv, &dev, &num_packets, &dst_ip, &verbose);
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
	
	/* get network number and mask associated with capture device */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
		    dev, errbuf);
		net = 0;
		mask = 0;
	}
	
	printInfo(dev, num_packets, filter_exp);

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
	main_thread_sigaction.sa_handler = my_sigint_handler;
    sigemptyset(&main_thread_sigaction.sa_mask);
    main_thread_sigaction.sa_flags = 0; 
    
   

	if(sigaction(SIGINT, &main_thread_sigaction, NULL) == -1){
		perror("Sigaction()");
	}
	
	
	/* Initializing the list of hosts that are trying to scan the target given in the rule (filter_exp) */
	head = NULL;
	
	
	printf("Begin scanning at: ");
	print_now();
	time_t begTime = my_now();
    
	/* now we can set our callback function */
	pcap_loop(handle, num_packets, got_packet, NULL);
	break_thread = true;
	/* WAITING ALL THE THREADS TO FINISH */
	node_t * current = head;
	printf("WAITING\n");
	void * end;
	
	while(current != NULL){
		pthread_join(current->thread, &end);
		current = current->next;
	}
	
	printf("End Scanning at: \n");
	time_t endTime = my_now();
	print_now();
	
	printf("*** TOTAL TIME ELAPSED %.02f seconds***\n", difftime(endTime, begTime));
	
	
	print_list(head);
	
	/* cleanup */
	free_list(head);
	pcap_freecode(&fp);
	pcap_close(handle);
	free(dev);
	printf("\nCapture complete.\n");
	return EXIT_SUCCESS;
}
