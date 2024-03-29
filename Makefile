# Makefile for RSA_Tutor

CC = gcc
CFLAGS = -Wall -Wextra -pedantic -std=c11
LIB = -lgmp
SRC = RSA_Tutor.c
OUT = RSA_Tutor

all: $(OUT)

$(OUT): $(SRC)
	$(CC) $(CFLAGS) -o $@ $^ $(LIB)

clean:
	rm -f $(OUT)

.PHONY: all clean

