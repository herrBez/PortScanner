#ifndef __MY__FLAG__UTILITY__
#define __MY__FLAG__UTILITY__
#include "important_header.h"

u_char get_syn_scan_flags();
u_char get_fin_scan_flags();
u_char get_xmas_scan_flags();
u_char get_ack_scan_flags();
u_char get_null_scan_flags();
void print_tcp_flags(u_char flag);

#endif
