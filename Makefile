CC=gcc
CFLAGS= 

portscanner:	portscanner.o
	$(CC) -o portscanner portscanner.o $(CFLAGS) 	
clean:
	rm *.o portscanner

