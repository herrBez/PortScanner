# the compiler: gcc for C program, define as g++ for C++
CC = gcc

# compiler flags:
#  -g    adds debugging information to the executable file
#  -Wall turns on most, but not all, compiler warnings
# 
CFLAGS  = -g -Wfatal-errors -Werror -Wall

ADDITIONAL_FLAGS = -pthread -lpcap



SRCS = ./include/*.c

OBJS = $(SRCS:.c=.o)
# the build target executable:
TARGET = port_scanner_detector
all: $(TARGET)

$(TARGET): $(TARGET).c
	$(CC) $(CFLAGS) $(ADDITIONAL_FLAGS) $(SRCS) -o $(TARGET) $(TARGET).c




clean:
	rm *.o ./include/*.o $(TARGET)

