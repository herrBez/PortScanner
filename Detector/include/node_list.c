/* implementation of node_list.h */
#include "node_list.h"
#include "_my_time.h"

void printNode(node_t * n){
	printf("\t[Score = %d][SRC IP = %s]", n->total_score, n->ip_src);
	printf("[UDP=%d][ICMP=%d][IP=%d][UK=%d]\n", n->udp, n->icmp, n->ip, n->unknown);
	printf("\t\t[TCP=%d][SYN %u, ACK %u, FIN %u, NULL %u, XMAS %u, UNKNWON %u]\n", 
		n->tcp, n->tcp_syn_scan, n->tcp_ack_scan, n->tcp_fin_scan, n->tcp_null_scan, n->tcp_xmas_scan, n->tcp_unknown_scan);
	printf("\tTCP PORTS{");
	print_list_my_port(n->tcp_port_list);
	printf("}\n");
}



void print_list(node_t * head){
	node_t * current = head;
	int i = 1;
	printf("******************************\n");
	printf("*** PRINTING THE NODE LIST ***\n");
	printf("******************************\n");
	if(current == NULL){
		printf("\n<The List is empty>\n");
		return;
	}
	

    while (current != NULL) {
		printf("***********************************************************************\n\n");
		printf("#%d. ", i++);
		printNode(current);
		printf("Scan detected %u\n", current->scan_detected); 
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
	n->tcp_syn_scan = 0;
	n->tcp_xmas_scan = 0;
	n->tcp_ack_scan = 0;
	n->tcp_null_scan = 0;
	n->tcp_fin_scan = 0;
	n->tcp_unknown_scan = 0;
	n->tcp_port_list = NULL;
	n->udp_port_list = NULL;
	n->udp = 0;
	n->icmp = 0;
	n->unknown = 0;
	n->ip = 0;
	n->scan_detected = 0;
	n->init_time = my_now();
	n->end_time = my_now();
	n->next = NULL;
	return n;
}

node_t * contains_node(node_t * head, char * ip_src){
	bool is_contained = false;
	node_t * current = head;
	while(current != NULL){
		if(strcmp(current->ip_src, ip_src) == 0){
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


void push(node_t ** head, char * ip_src) {
	node_t * current = *head;

	if(*head == NULL){
		//printf("Adding the first element %s \n", ip_src);
		*head = newNode(ip_src);
		return;
	}
    while (current->next != NULL) {
        current = current->next;
    }

    /* now we can add a new variable */
    current->next = newNode(ip_src);
}




void free_list(node_t * head){
	node_t * curr;
	while ((curr = head) != NULL) { 
		head = head->next;          
		free(curr->tcp_port_list);
		free(curr->udp_port_list);
		free (curr->ip_src);
		free (curr);                
	}
}

bool _equals(node_t n1, node_t n2){
	return strcmp(n1.ip_src, n2.ip_src) == 0;
}


