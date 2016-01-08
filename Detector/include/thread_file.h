#ifndef __MY__THREAD__FILE__H__
#define __MY__THREAD__FILE__H__

#include "important_header.h"
/* Initialized in port_scanner_detector to false. If true all the threads stops after the next cycle */
extern bool break_thread;
/* contains the fixed time interval 300 ms */
extern struct timespec _my_time; 

/* Function that control the score of all the nodes and set the score again to 0 */
void controlScore(node_t * n);
/* function passed to pthread_create() 
 * Each _my_time (default 300 ms) check the
 * "score" of the given node (source ip)
 */
void * thread_function(void * _node);



#endif
