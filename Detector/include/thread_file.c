#include "important_header.h"

/* Extern variable initialized in the main function of port_scanner_detector.c */
struct timespec _my_time; 


/** Function that control the score of all the nodes and set the score again to 0 */
void controlScore(node_t * n){
	int i;
	int tot_detected = 0;
	for(i = 0; i < INDEX_SIZE; i++){
		if(n->tcp_actual_score[i] >= PORT_SCAN_SCORE){
			printf("*** %7s TCP SCAN FROM %s dectected\n", index_to_string(i), n->ip_src);
			n->tcp_scan_detected[i]++;
			tot_detected++;
		}
		n->tcp_actual_score[i] = 0;
	}
	
	if(n->udp_actual_score >= PORT_SCAN_SCORE){
		printf("=== UDP SCAN FROM %s ===\n", n->ip_src);
		n->udp_scan_detected++;
	}
	n->udp_actual_score = 0;
	
	
}

/** function passed to pthread_create() 
 * Each _my_time (default 300 ms) check the
 * "score" of the given node (source ip)
 */
void * thread_function(void * _node){	
	node_t * n = (node_t *) _node;
	while(!break_thread){
		if(nanosleep(&_my_time, NULL) != 0){
			perror("Nanosleep():");
			break;
		}
		controlScore(n);
		
	}
	return NULL;
}