#ifndef __MY_NODE_LIST_H__
#define __MY_NODE_LIST_H__

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <pthread.h>
#include "port_list.h"
#define PORT_SCAN_SCORE 21


typedef struct node {
	unsigned int actual_score; 	/* actual_score: each 300 ms is reset to 0 */
	unsigned int total_score; 
	unsigned int udp; 			/* Counter of tcp packets */
	unsigned int icmp; 			/* Counter of ICMP packets */
	unsigned int unknown; 		/* Counter of packets with unknown protocol */
	unsigned int ip; 			/* Counter of ip packets that are not udp, nor icmp, nor tcp */
	unsigned int scan_detected; /* counter of detected scans */
	unsigned int tcp; 			/* Counter of tcp packets received from  the ip_src */
	unsigned int tcp_syn_scan;
	unsigned int tcp_xmas_scan;
	unsigned int tcp_ack_scan;
	unsigned int tcp_null_scan;
	unsigned int tcp_fin_scan;
	unsigned int tcp_unknown_scan;
	time_t init_time;
	time_t end_time;
	pthread_t thread;
	my_port * port_list;
	char * ip_src;
	struct node *next;
}node_t;

node_t * newNode(char * actual_adress);

/* print a single node */
void printNode(node_t * n);
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
