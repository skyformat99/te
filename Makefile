#
# Makefile for te
#

CC=cc
CFLAGS=-s 
SRC=$(wildcard *.c)
PREFIX=/usr/local

all:
	$(CC) $(CFLAGS) $(SRC) -o $(SRC:.c=)


install: all
	install -Dm755 $(SRC:.c=) "${PREFIX}/bin/$(SRC:.c=)"
	mkdir "${PREFIX}/share/te/"
	install -Dm755 "txt/mac-prefixes" "${PREFIX}/share/te/"
uninstall:
	rm -f /usr/local/bin/$(SRC:.c=)
	rm -rf ${PREFIX}/share/te/

debug: $CFLAGS += -DDEBUG

clean:
	rm $(SRC:.c=)
