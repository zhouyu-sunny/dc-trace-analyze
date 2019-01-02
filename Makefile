CC=gcc
CFLAGS=-c -Wall -O3
LDFLAGS= -lpcap
OBJS=main.o hash.o congestion.o loss.o packet.o sample.o
TARGETS=main

all: $(TARGETS)

main: $(OBJS)
	gcc -o analyze $(OBJS) -lpcap
	rm *.o


