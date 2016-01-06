#ifndef __MY_NODE_LIST_H__
#define __MY_NODE_LIST_H__

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include "port_list.h"
#define PORT_SCAN_SCORE 21


typedef struct node {
  int score;
  char * ip_src;
  unsigned int tcp;
  my_port * port_list;
 
  
  int port_index;
  unsigned int udp;
  unsigned int icmp;
  unsigned int unknown;
  unsigned int ip;
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
void push(node_t * head, char * ip_src);


#endif
