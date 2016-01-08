#ifndef __MY__THREAD__FILE__H__
#define __MY__THREAD__FILE__H__

#include "important_header.h"

extern bool break_thread;
/* contains the fixed time interval 300 ms */
extern struct timespec _my_time; 
void controlScore(node_t * n);
void * thread_function(void * _node);



#endif
