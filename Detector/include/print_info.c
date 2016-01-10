#include "important_header.h"


void printHelp(char * program_name){
	printf("=========================================\n");
	printf("=== Portscanner Detector help message ===\n");
	printf("=========================================\n");
	printf("Usage: %s [options]\n", program_name);
	printf("Options:\n\n");
	printf("\t --help\n");
	printf("\t -h \t print this help and exit\n");
	printf("\t --save-the-port\n");
	printf("\t -s \t save all the tcp ports requested from the potential attackers\n");
	printf("\t --device\n");
	printf("\t -d \t specify a device to use (e.g. wlan0, eth0) you can get those devices using the command ifconfig\n");
	printf("\t --verbose\n");
	printf("\t -v \t verbose output\n");
	printf("\t --dst-ip\n");
	printf("\t -i \t give a destination ip adress (please use ifconfig to find the correct one) \n");
	printf("\t --max-num-of-packets\n");
	printf("\t -m \t maximum number of catchable packets after which the program ends\n");
	printf("\t --log-file\n");
	printf("\t -l \t Save the output in a .tex file\n");
	printf("\nAuthors: Simon Targa, Mirko Bez\n");
	exit(EXIT_SUCCESS);
}


void printInfo(char * dev, int num_packets, char * filter_exp){
	printf("   ****************************\n");
	printf("   *** A PORT SCAN DETECTOR ***\n");
	printf("   ****************************\n\n");

	printf("*****************************************************\n");
	/* print capture info */
	printf("Device: %s\n", dev);
	printf("Number of packets ");

	if(num_packets == -1)
		printf("infinity: i.e. until Ctrl-C occurs\n");
	else 
		printf("%d\n", num_packets);
	printf("Filter expression: %s\n", filter_exp);

	printf("*****************************************************\n\n\n");
}
