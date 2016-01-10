/* implementation of node_list.h */
#include "important_header.h"

void printNode(node_t * n){
	int i;
	
	printf("Potential Port Scanner IP: %s\n", n->ip_src);
	printf("\t*** Summary: received packets ***\n");
	printf("\t[TCP=%u][UDP=%u][ICMP=%u][IP=%u][UNKNOWN=%u]\n", n->tcp, n->udp, n->icmp, n->ip, n->unknown);
	printf("\t*** TCP PROTOCOL ***\n");
	printf("\t\t[TCP=%d][SYN %u, ACK %u, FIN %u, NULL %u, XMAS %u, MAIMON %u, UNKNWON %u]\n", 
		n->tcp, n->tcp_syn, n->tcp_ack, n->tcp_fin, n->tcp_null, n->tcp_xmas, n->tcp_maimon, n->tcp_unknown);
	
	for(i = 0; i <= INDEX_TCP; i++){
		printf("\t\t\tTOT SCORE[%7s]:\t\t%3u\n", index_to_string(i), n->tcp_total_score[i]);
	}
	printf("\t\t\t *** \t\t\t\n");
	for(i = 0; i <= INDEX_TCP; i++){
		printf("\t\t\tScan [%7s] detected:\t %d\n", index_to_string(i), n->tcp_scan_detected[i]);
	}
	printf("\t\tTCP PORTS{");
	print_list_my_port(n->tcp_port_list);
	printf("}\n");
	printf("\t*** UDP PROTOCOL ***\n");
	printf("\tTOT Packets %u", n->udp);
	printf("\t\tTOT SCORE UDP:\t\t %3u\n", n->udp_total_score);
	printf("\t\tUDP Scan detected:\t%3u\n", n->udp_scan_detected);
	printf("\t\tUDP PORTS{");
	print_list_my_port(n->udp_port_list);
	printf("}\n");
}

char * index_to_string(int index) {
	switch(index){
		case INDEX_SYN: return "SYN";		
		case INDEX_XMAS: return "XMAS";		
		case INDEX_ACK:	return "ACK";
		case INDEX_MAIMON: return "MAIMON";
		case INDEX_NULL: return "NULL";
		case INDEX_FIN:	return "FIN";
		case INDEX_UNKNOWN:	return "UNKNOWN";
		case INDEX_TCP: return "TCP"; 		
	}
	return "";
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
		printf("\n************************************************************************\n\n");
        current = current->next;
    }
}

node_t * newNode(char * actual_adress){
	node_t * n = malloc(sizeof(node_t));
	n->ip_src = malloc(sizeof(char) * (strlen(actual_adress) + 1));
	strcpy(n->ip_src, actual_adress);
	int i;
	for(i = 0; i <= INDEX_TCP; i++){
		n->tcp_total_score[i] = 0;
		n->tcp_actual_score[i] = 0;
		n->tcp_scan_detected[i] = 0;
	}
	
	n->tcp = 0;
	n->tcp_syn = 0;
	n->tcp_xmas = 0;
	n->tcp_ack = 0;
	n->tcp_null = 0;
	n->tcp_fin = 0;
	n->tcp_maimon = 0;
	n->tcp_unknown = 0;
	n->tcp_port_list = NULL;
	n->udp_port_list = NULL;
	n->udp = 0;
	n->icmp = 0;
	n->unknown = 0;
	n->ip = 0;

	n->udp_scan_detected = 0;
	n->udp_total_score = 0;
	n->udp_actual_score = 0;
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
		free_list_my_port(curr->tcp_port_list);
		free_list_my_port(curr->udp_port_list);
		free (curr->ip_src);
		free (curr);                
	}
}

bool _equals(node_t n1, node_t n2){
	return strcmp(n1.ip_src, n2.ip_src) == 0;
}


