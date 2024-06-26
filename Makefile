CC = gcc
DEBUG = -g
CFLAGS = -Wall -Wextra -Wshadow -Wunreachable-code \
	-Wredundant-decls -Wmissing-declarations \
	-Wold-style-definition -Wmissing-prototypes \
	-Wdeclaration-after-statement -Wno-return-local-addr \
	-Wunsafe-loop-optimizations -Wuninitialized -Werror \
	-Wno-unused-parameter
LDFLAGS = -lz
HEADERS = viktar.h
PROG1 = viktar
PROGS = $(PROG1)

all: $(PROGS)

$(PROG1): $(PROG1).o
	$(CC) $(DEBUG) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(PROG1).o: $(PROG1).c $(HEADERS)
	$(CC) $(DEBUG) $(CFLAGS) -c $<

clean cls:
	rm -f $(PROGS) *.o *~ \#*

tar:
	tar cvfa viktar_${LOGNAME}.tar.gz *.[c] [mM]akefile

