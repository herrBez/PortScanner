CC=gcc
CFLAGS=-Werror

portscanner:	portscanner.o raw_socket_scan.o
	$(CC) -o portscanner raw_socket_scan.o portscanner.o $(CFLAGS) 	
clean:
	rm *.o portscanner

