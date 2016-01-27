srcdir = $(PWD)
COMMON_DIR=../common
include Makefile.vars
include Makefile.rules

SRCS = $(wildcard *.c)
OBJS = $(subst .c,.o,$(SRCS)) debug.o psl_interface.o utils.o

all: pslse

pslse: $(OBJS)
	$(call Q,CC, $(CC) $(CFLAGS) -o $@ $^ -lpthread, $@)

clean:
	rm -rf *.[od] *.d-e gmon.out pslse

.PHONY: clean all
