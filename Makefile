CC=gcc
CFLAGS= -Wall -Werror

portscanner:	portscanner.o
	$(CC) -o portscanner portscanner.o $(CFLAGS) 	
clean:
	rm *.o

