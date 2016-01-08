/* implementation of port_list.h */
#include "port_list.h"


/* return a new my port element */
my_port * new_my_port(int dst_port){
	my_port * mp = malloc(sizeof(my_port));
	mp->port = dst_port;
	mp->times = 1;
	mp->next = NULL;
}

/* add a new element at the end of the list */
void push_my_port(my_port * head, int dst_port){
	my_port * current = head;
    while (current->next != NULL) {
        current = current->next;
    }

    /* now we can add a new variable */
    current->next = new_my_port(dst_port);
}

/* check if a dst_port is already contained in the list: returns the element 
 * if it's contained otherwise null */
my_port * contains_my_port(my_port * head, int dst_port){
	bool is_contained = false;
	my_port * current = head;
	while(current != NULL){
		int res = current->port - dst_port;
		if(res == 0){
			is_contained = true;
			break;
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

/* Print a my_port element */
void print_my_port(my_port * mp){
	printf("(%d, #%d)", mp->port, mp->times);
}
/* Print a list of my port element */
void print_list_my_port(my_port * head){
	if(head == NULL){
		printf("<The List is empty>");
		return;
	}
	int i = 1;
    my_port * current = head;

    while (current != NULL) {
		print_my_port(current);
        current = current->next;
    }
}
/* Frees a list of my port elements */
void free_list_my_port(my_port * head){
	my_port * curr;
	while ((curr = head) != NULL) { // set curr to head, stop if list empty.
		head = head->next;          // advance head to next element.
		free (curr);                // delete saved pointer.
	}
}
