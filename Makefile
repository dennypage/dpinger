#CC=clang
#CFLAGS=-Wall -Wextra -pthread -g -O2

all: dpinger

.PHONY: clean
clean:
	rm -f dpinger
