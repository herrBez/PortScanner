# the compiler: gcc for C program, define as g++ for C++
CC = gcc

# compiler flags:
#  -g    adds debugging information to the executable file
#  -Wall turns on most, but not all, compiler warnings
# -Wfatal-errors to stop a the first error!
CFLAGS  = -g  -Werror -Wall

ADDITIONAL_FLAGS = -pthread -lpcap

# the build target executable:
TARGET = port_scanner_detector
COMPILE_OBJS = compile

SRCS =./include/node_list.c ./include/flag_utility.c  ./include/_my_time.c   ./include/output_file_utility.c  ./include/port_list.c  ./include/print_info.c  ./include/thread_file.c 

OBJS = $(SRCS:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $(ADDITIONAL_FLAGS) $(OBJS) -o $(TARGET) $(TARGET).c

$(COMPILE_OBJS): $(SRCS)
	$(CC) $(CFLAGS) $(ADDITIONAL_FLAGS) -c $(SRCS)


clean:
	rm $(OBJS) $(TARGET)

