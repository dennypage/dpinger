#CC=gcc
#WARNINGS=-Wall -Wextra -Wformat=2

#CC=clang
#WARNINGS=-Weverything -Wno-padded -Wno-disabled-macro-expansion

#CC=ccc-analyzer
#WARNINGS=

CFLAGS=${WARNINGS} -pthread -g

all: dpinger
