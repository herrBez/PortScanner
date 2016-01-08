/* implementation of node_list.h */
#include "node_list.h"

void printNode(node_t * n){
	int i = 0;
	printf("[Score = %d][SRC IP = %s][TCP=%d]", n->total_score, n->ip_src,n->tcp);
	printf("[UDP=%d][ICMP=%d][IP=%d][UK=%d]", n->udp, n->icmp, n->ip, n->unknown);
	printf("TCP PORTS{");
	print_list_my_port(n->port_list);
	printf("}\n");
}



void print_list(node_t * head){
	printf("******************************\n");
	printf("*** PRINTING THE NODE LIST ***\n");
	printf("******************************\n");
	if(head == NULL){
		printf("\n<The List is empty>\n");
		return;
	}
	int i = 1;
    node_t * current = head;

    while (current != NULL) {
		printf("***********************************************************************\n\n");
		printf("#%d. ", i++);
		printNode(current);
		printf("\n************************************************************************\n\n");
        current = current->next;
    }
}

node_t * newNode(char * actual_adress){
	node_t * n = malloc(sizeof(node_t));
	n->ip_src = malloc(sizeof(char) * (strlen(actual_adress) + 1));
	strcpy(n->ip_src, actual_adress);
	n->total_score = 0;
	n->actual_score = 0;
	n->tcp = 0;
	n->port_list = NULL;
	n->udp = 0;
	n->icmp = 0;
	n->unknown = 0;
	n->ip = 0;
	n->next = NULL;
	return n;
}

node_t * contains_node(node_t * head, char * ip_src){
	bool is_contained = false;
	node_t * current = head;
	while(current != NULL){
		int res = strcmp(current->ip_src, ip_src);
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

bool contains(node_t * head, char * ip_src){
	return contains_node(head,ip_src) != NULL;
}


void push(node_t * head, char * ip_src) {
    node_t * current = head;
    while (current->next != NULL) {
        current = current->next;
    }

    /* now we can add a new variable */
    current->next = newNode(ip_src);
}




free_list(node_t * head){
	node_t * curr;
	while ((curr = head) != NULL) { // set curr to head, stop if list empty.
		head = head->next;          // advance head to next element.
		free(curr->port_list);
		free (curr->ip_src);
		free (curr);                // delete saved pointer.
	}
}

