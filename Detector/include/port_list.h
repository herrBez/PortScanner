#ifndef __MY_PORT_LIST_H__
#define __MY_PORT_LIST_H__

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>


typedef struct _my_port{
	unsigned short port;
	unsigned short times;
	struct _my_port * next;
}my_port;

/* return a new my port element */
my_port * new_my_port(int dst_port);
/* add a new element at the end of the list */
void push_my_port(my_port * head, int port);
/* 
 * check if a dst_port is already contained in the list: returns the element 
 * if it's contained otherwise null 
 */
my_port * contains_my_port(my_port * head, int dst_port);
/* Print a my_port element */
void print_my_port(my_port * mp);
/* Print a list of my port element */
void print_list_my_port(my_port * head);
/* Frees a list of my port elements */
void free_list_my_port(my_port * head);





#endif
