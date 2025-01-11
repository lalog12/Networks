# C Compiler = gcc
CC = gcc

#Libraries that will be used
LIBS = -lpcap

#Flags we want when compiling
CFLAGS = -g -Wall -pedantic -std=gnu99

all: trace

trace: trace.c
		$(CC) $(CFLAGS) -o $@ trace.c $(LIBS)

clean:
		rm -f trace