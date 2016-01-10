#include "output_file_utility.h"
#include <stdio.h>
#include <stdlib.h>


void fprint_tabs(FILE * fd, int tabs){
	int i;
	for(i = 0; i < tabs; i++){
		fputc('\t', fd);
	}
}

void output_file_f(char * output_file_name, node_t * head, time_t begin_time, time_t end_time, double elapsed_time, int count, bool _get_all_info, char * filter_expression, char * dev){
		//printf("I will try to write the result in a file named '%s'\n", output_file_name);
		FILE * output = fopen(output_file_name, "w");
		if(output == NULL){
			fprintf(stderr, "Cannot open the file %s. Have you enough permissions to do that?\n", output_file_name);
			return;
		}
		int src = 0;
		fprintf(output, "\\documentclass[a4paper]{scrartcl}\n");
		fprintf(output, "\\usepackage{fullpage}\n");
		fprintf(output, "\\author{Simon Targa \\and Mirko Bez}\n");
		fprintf(output, "\\title{Port Scan Detector Output File}\n");
		fprintf(output, "%% filename: %s\n", output_file_name); 
		fprintf(output, "\\begin{document}\n");
		fprintf(output, "\\maketitle{}\n");
		
		
		int tabs = 0;
		fprintf(output, "\\section{List of potential attackers}\n");
		fprintf(output, "\\emph{ICMP, UDP, IP, UK (Unknown), TCP indicate the number of the packets of that type received.} \\\\ \\\\ \n");
		fprintf(output, "\\begin{tabular}{| c | c | c | c | c | c | c | c | c | }\n");
		fprint_tabs(output, ++tabs);
		fprintf(output, "\\hline\n");
		fprint_tabs(output, tabs);
		fprintf(output, "ID & IP Address & First & Last  & ICMP & UDP & IP & UK & TCP \\\\ \n");
		fprintf(output, "   &            & Packet & Packet &     &    &    &     & \\\\ \n");
		fprint_tabs(output, tabs);
		fprintf(output, "\\hline\n");
		node_t * current = head;
		char * buffer_init = calloc(100, sizeof(char));
		char * buffer_end = calloc(100, sizeof(char));
		while (current != NULL) {
			src++;
			fprint_tabs(output, tabs);
			
			strftime(buffer_init, sizeof(char)*100, "%d.%m.%g %H:%M:%S", localtime(&current->init_time));
			strftime(buffer_end, sizeof(char)*100, "%d.%m.%g %H:%M:%S", localtime(&current->end_time));

			fprintf(output, "%d & %s & %s & %s & %3u & %3u & %3u & %3u & %3u \\\\ \n", 
				src, current->ip_src, buffer_init, buffer_end, current->icmp, current->udp, current->ip, current->unknown, current->tcp);
			fprint_tabs(output, tabs);
			fprintf(output,"\\hline\n");
			current = current->next;
		}
		free(buffer_init);
		free(buffer_end);

		fprint_tabs(output, --tabs);
		fprintf(output, "\\end{tabular}\n");
		
		fprintf(output, "\\section{TCP Details}\n");
		fprintf(output, "\\emph{SYN, FIN, XMAS, NULL, ACK, UK (Unkown) indicate the number of the tcp packets of that type received.} \\\\ \\\\ \n");

		fprintf(output, "\\begin{tabular}{| c | c | c | c | c | c | c | c | c | c | }\n");
		fprintf(output, "\\hline \n");
		fprintf(output, "ID & IP-Address & TCP & SCAN & SYN  & FIN & XMAS & NULL & ACK & UK \\\\ \n");
		fprintf(output, " &  & & DETECTED &   &  &  &  &  &  \\\\ \n");
		unsigned int tot_scan_detected = 0;
		unsigned int diff_sources = 0;
		fprintf(output, "\\hline \n");
		current = head;
		src = 0;
		while (current != NULL) {
			src++;
			fprint_tabs(output, tabs);
			tot_scan_detected += current->scan_detected;
			if(current->scan_detected != 0)
				diff_sources++;
			fprintf(output, "%d & %s & %3u & %3u & %3u & %3u & %3u & %3u & %3u & %3u \\\\ \n",
				src, current->ip_src, current->tcp, current->scan_detected, current->tcp_syn_scan, current->tcp_fin_scan,
				current->tcp_xmas_scan, current->tcp_null_scan, current->tcp_ack_scan, current->tcp_unknown_scan);
			
			
			fprint_tabs(output, tabs);
			fprintf(output,"\\hline\n");
			current = current->next;
		}
		fprintf(output, "\\end{tabular}\n");

		fprintf(output, "\\section{Summary}\n");
		fprintf(output, "\\emph{List containing the result and some meta data} \\\\ \\\\ \n");
		
		fprintf(output, "\\begin{tabular}{| l | r |}\n");
		fprintf(output, "\\hline\n");
		fprintf(output, "Filter Expression & %s \\\\ \n", filter_expression);
		fprintf(output, "Device used & %s \\\\ \n", dev);
		fprintf(output, "Number of TCP scan detected & %u \\\\ \n", tot_scan_detected);
		fprintf(output, "Number of different scanners & %u \\\\ \n", diff_sources);
		fprintf(output, "Number of different sources (i.e. \\# potential attackers) & %d \\\\ \n", src);
		fprintf(output, "Number of received packets &  %d \\\\ \n", count);
		
		fprintf(output, "Scan begin & %s \\\\ \n", asctime (localtime(&begin_time)));
		fprintf(output, "Scan end & \t%s \\\\ \n", asctime(localtime(&end_time)));
		fprintf(output, "Total Elapsed time & %.0f seconds \\\\ \n", elapsed_time);
		fprintf(output, "\\hline\n");
		fprintf(output, "\\end{tabular}\n");
		
		
		if(_get_all_info){
			int total_line = 0;
			fprintf(output, "\\newpage");
			fprintf(output, "\\section{TCP PORT FREQUENCY}\n");
			fprintf(output, "\\emph{List of the tcp port visited from the single host and the times} \\\\ \\\\ \n");
			
			fprintf(output, "\\noindent\\begin{minipage}[b]{0.5\\linewidth}");
			fprintf(output, "\\begin{tabular}{| c | c | c | c | c |}\n");
			fprintf(output, "\\hline\n");
			fprintf(output, "ID & IP & TOT & PORT & TIMES \\\\ \n");
			fprintf(output, "   &    & TCP &      &       \\\\ \n");
			fprintf(output, "\\hline\n");
			current = head;
			src = 0;
			while(current != NULL){
				src++;
				
				fprintf(output, "%d & %s & %d", src, current->ip_src, current->tcp);
				my_port * my_p = current->tcp_port_list;
				int line = 0;
				if(my_p == NULL){
					fprintf(output, " & & \\\\ \n");
					total_line++;
				}
				while(my_p != NULL){
					if(line == 0){
						fprintf(output, " & %d & %d \\\\ \n", my_p->port, my_p->times);
						line++;
						total_line++;
					}
					else {
						fprintf(output, "& & & %d & %d \\\\ ", my_p->port, my_p->times);
						total_line++;
					}
					if(total_line % 40 == 0 && total_line != 0){
						fprintf(output, "\\hline\\end{tabular}\\end{minipage} \\hfill\\begin{minipage}[b]{0.5\\linewidth}");
						fprintf(output, "\\begin{tabular}{| c | c | c | c | c |}\n");
						fprintf(output, "\\hline\n");
						fprintf(output, "ID & IP & TOT & PORT & TIMES \\\\ \n");
						fprintf(output, "   &    & TCP &      &       \\\\ \n");
						fprintf(output, "\\hline\n");
					}
					
					my_p = my_p->next;
				}
				if(total_line % 40 == 0 && total_line != 0){
						fprintf(output, "\\hline\\end{tabular}\\end{minipage} \\hfill\\begin{minipage}[b]{0.5\\linewidth}");
						fprintf(output, "\\begin{tabular}{| c | c | c | c | c |}\n");
						fprintf(output, "\\hline\n");
						fprintf(output, "ID & IP & TOT & PORT & TIMES \\\\ \n");
						fprintf(output, "   &    & TCP &      &       \\\\ \n");
						fprintf(output, "\\hline\n");
					}
				
				current = current->next;
			}
			fprintf(output, "\\hline\n");
			fprintf(output, "\\end{tabular}\n");
			fprintf(output, "\\end{minipage}\\hfill");
		}
		
		

		fprintf(output, "\\end{document}\n");
		if(fclose(output) == EOF){
			fprintf(stderr, "I could not close the file successfully\n");
		} else {
			FILE * fp = fopen(output_file_name, "r");
			fseek(fp, 0L, SEEK_END);
			size_t sz = ftell(fp) + 1;
			
			double size = ((double)(sz))/1024; 
			printf("Generated a file with a size of ~ %.1f KB\n", size);
			fclose(fp); 
			printf("Compile the file using the command 'pdflatex %s'", output_file_name);

		}
	
}
