#include "_my_time.h"

/* Function that return the actual time in form of a time_t */
time_t my_now(){
	time_t rawtime;
	time ( &rawtime );
	return rawtime;
}

/* function that print the current local time */
void print_now(){
	time_t rawtime;
	struct tm * timeinfo;

	time ( &rawtime );
	timeinfo = localtime ( &rawtime );
	printf ( "Current local time and date: %s", asctime (timeinfo) );
}

char * time_t_to_string(time_t t){
	return asctime (localtime(&t));
}



