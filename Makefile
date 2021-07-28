
CC = cc

BUILD_DIR = ./build
INCLUDES_DIR := ./include

CFLAGS = -I$(INCLUDES_DIR) -g -std=c11 -fPIC

ASPRINTF_SRC = src/asprintf.c
ASPRINTF_CFLAGS = $(CFLAGS)
ASPRINTF_LDFLAGS = -lc

RWTP_SRC = src/rwtp.c
RWTP_CFLAGS = $(CFLAGS) -Wall
RWTP_LDFLAGS = -lsodium -lmsgpackc -lc

all: rwtp

asprintf.o:
	$(CC) -c $(ASPRINTF_SRC) $(ASPRINTF_CFLAGS) -o $(BUILD_DIR)/asprintf.o

rwtp.o:
	$(CC) -c $(RWTP_SRC) $(RWTP_CFLAGS) -o $(BUILD_DIR)/rwtp.o

rwtp: rwtp.o asprintf.o
	$(CC) $(BUILD_DIR)/rwtp.o $(BUILD_DIR)/asprintf.o $(ASPRINTF_LDFLAGS) $(RWTP_LDFLAGS) -shared -o $(BUILD_DIR)/librwtp.so
