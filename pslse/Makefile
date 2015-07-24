srcdir = $(PWD)
COMMON_DIR=../common
include Makefile.vars
include Makefile.rules

OBJS = pslse.o client.o cmd.o debug.o job.o mmio.o parms.o psl.o shim_host.o psl_interface.o utils.o

all: pslse

pslse: $(OBJS)
	$(call Q,CC, $(CC) $(CFLAGS) -o $@ $^ -lpthread -lrt, $@)

clean:
	rm -f *.[od] gmon.out pslse

.PHONY: clean all
