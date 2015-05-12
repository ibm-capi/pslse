srcdir = $(PWD)
COMMON_DIR=../common
include Makefile.vars
include Makefile.rules

OBJS = debug.o utils.o

all: debug

debug: $(OBJS) main.c
	$(call Q,CC, $(CC) $(CFLAGS) -o $@ $^ -lpthread -lrt, $@)

clean:
	rm -f *.[od] debug

.PHONY: clean all
