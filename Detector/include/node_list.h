#ifndef __MY_NODE_LIST_H__
#define __MY_NODE_LIST_H__

#include "important_header.h"
#define PORT_SCAN_SCORE 21

#define INDEX_TCP 		0
#define INDEX_SYN		1
#define INDEX_XMAS		2
#define INDEX_ACK		3
#define INDEX_MAIMON	4
#define INDEX_NULL		5
#define INDEX_FIN		6
#define INDEX_UNKNOWN	7 


#define INDEX_SIZE INDEX_UNKNOWN+1 

/* Convert the constant to a readable string */
char * index_to_string(int index);


typedef struct node {
	unsigned int ip; 			/* Counter of ip packets that are not udp, nor icmp, nor tcp */
	unsigned int icmp; 			/* Counter of ICMP packets */
	unsigned int unknown; 		/* Counter of packets with unknown protocol */
	

	
	/* TCP PROTOCOL PLACE HOLDERS */
	unsigned int tcp_actual_score[INDEX_SIZE]; 	/* actual_score: each 300 ms is reset to 0 */
	unsigned int tcp_total_score[INDEX_SIZE]; 
	unsigned int tcp_scan_detected[INDEX_SIZE]; /* counter of detected scans */
	unsigned int tcp[INDEX_SIZE]; 			/* Counter of tcp packets received from  the ip_src */
	
	
	
	/* UDP PROTOCOL PLACE HOLDERS */
	unsigned int udp_actual_score; 	/* UDP is slower I will check it only after a while(300ms*10?)  */
	unsigned int udp_total_score; 
	unsigned int udp; 			/* Counter of tcp packets */
	unsigned int udp_scan_detected;
	
	
	time_t init_time;
	time_t end_time;
	pthread_t thread;
	my_port * tcp_port_list;
	my_port * udp_port_list;
	char * ip_src;
	struct node *next;
}node_t;



node_t * new_node(char * actual_adress);

/* print a single node */
void print_node(node_t * n);
/* Print all element of a list using the function printNode */
void print_list(node_t * head);
/* 
 * Check if the list head already contains the given ip_src and returns  
 * the element if ip_src is found otherwise nulls
 */
node_t * contains_node(node_t * head, char * ip_src);
/* 
 * Check if the list head already contains the given ip_src and returns  
 * true if the element is contained otherwise false
 */
bool contains(node_t * head, char * ip_src);
/* Add a new element at the end of the linked list */
void push(node_t ** head, char * ip_src);
/* free list */
void free_list(node_t * head);

bool _equals(node_t n1, node_t n2); 

#endif
