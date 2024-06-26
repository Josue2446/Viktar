CC = gcc
DEBUG = -g
CFLAGS = -Wall -Wextra -Wshadow -Wunreachable-code -Wredundant-decls -Wmissing-declarations -Wold-style-definition -Wmissing-prototypes -Wdeclaration-after-statement -Wno-return-local-addr -Wunsafe-loop-optimizations -Wuninitialized -Werror 

PROGS = viktar

all: $(PROGS)
 
$(PROGS): $(PROGS).o
	$(CC) $(CFLAGS) -o $@ $^ -lz -lbsd

$(PROGS).o: $(PROGS).c $(PROGS).h
	$(CC) $(CFLAGS) -c $<
 
clean cls:
	rm -f $(PROGS) *.o *~ \#*

tar:
	tar cvfa Lab2_${LOGNAME}.tar.gz *.[ch] [mM]akefile 
 


