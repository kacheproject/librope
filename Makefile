
CC = cc

TAU_DIR = ./tau

BUILD_DIR = ./build
INCLUDES_DIR := ./include

CFLAGS := -I$(INCLUDES_DIR) -g -std=c11 -fPIC

TEST_CFLAGS := $(CFLAGS) -I$(TAU_DIR) -Wall
TEST_LDFLAGS := -L$(BUILD_DIR) -lc -lsodium

ASPRINTF_SRC = src/asprintf.c
ASPRINTF_CFLAGS = $(CFLAGS)
ASPRINTF_LDFLAGS = -lc

RWTP_SRC = src/rwtp.c
RWTP_CFLAGS = $(CFLAGS) -Wall
RWTP_LDFLAGS = -lsodium -lmsgpackc -lc

TEST_RWTP_LDFLAGS := $(TEST_LDFLAGS) -lrwtp

all: rwtp

asprintf.o:
	$(CC) -c $(ASPRINTF_SRC) $(ASPRINTF_CFLAGS) -o $(BUILD_DIR)/asprintf.o

rwtp.o:
	$(CC) -c $(RWTP_SRC) $(RWTP_CFLAGS) -o $(BUILD_DIR)/rwtp.o

rwtp: rwtp.o asprintf.o
	$(CC) $(BUILD_DIR)/rwtp.o $(BUILD_DIR)/asprintf.o $(ASPRINTF_LDFLAGS) $(RWTP_LDFLAGS) -shared -o $(BUILD_DIR)/librwtp.so

rwtp-test: rwtp
	mkdir -p $(BUILD_DIR)/tests/rwtp
	$(CC) -c tests/rwtp/main.c $(TEST_CFLAGS) -o $(BUILD_DIR)/tests/rwtp/main.o
	$(CC) $(BUILD_DIR)/tests/rwtp/main.o $(TEST_RWTP_LDFLAGS) -o $(BUILD_DIR)/tests/rwtp/main

rwtp-test-run: rwtp-test
	LD_LIBRARY_PATH=$(BUILD_DIR):$LD_LIBRARY_PATH $(BUILD_DIR)/tests/rwtp/main

rwtp-test-run-valgrind: rwtp-test
	LD_LIBRARY_PATH=$(BUILD_DIR):$LD_LIBRARY_PATH valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes $(BUILD_DIR)/tests/rwtp/main
