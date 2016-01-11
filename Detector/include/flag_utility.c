#include "important_header.h"
/* Function that return the flags of the different scan types */
u_char get_syn_scan_flags(){
	return TH_SYN;
}

u_char get_fin_scan_flags(){
	return TH_FIN;
}

u_char get_xmas_scan_flags(){
	return TH_FIN | TH_URG | TH_PUSH;
}

u_char get_ack_scan_flags(){
	return TH_ACK;
}

u_char get_null_scan_flags(){
	return 0x0;
}

u_char get_maimon_scan_flags(){
	return TH_FIN | TH_ACK;
}

void print_tcp_flags(u_char flag){
	if((flag & 0x1) == 0x1)
		printf("FIN ");
	if((flag & 0x2) == 0x2) 
		printf("SYN ");
	if((flag & 0x4) == 0x4)
		printf("RST ");
	if((flag & 0x8) == 0x8)
		printf("PUSH ");
	if((flag & 0x10) == 0x10)
		printf("ACK ");
	if((flag & 0x20) == 0x20)
		printf("URG ");
	if((flag & 0x40) == 0x40)
		printf("ECE ");
	if((flag & 0x80) == 0x80)
		printf("CWR");
}

