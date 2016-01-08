#include "thread_file.h"

/* Extern variable initialized in the main function of port_scanner_detector.c */
struct timespec _my_time; 


/** Function that control the score of all the nodes and set the score again to 0 */
void controlScore(node_t * n){
	if(n->actual_score >= PORT_SCAN_SCORE){
		printf("*** SCAN FROM %s dectected ***\n", n->ip_src);
		n->scan_detected++;
	}
	n->actual_score = 0;
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
	printf("JOINING\n");
	return NULL;
}

