srcdir = $(PWD)
COMMON_DIR=../common
include Makefile.vars
include Makefile.rules

OBJS = pslse.o cmd.o job.o mmio.o parms.o psl.o shim_host.o psl_interface.o utils.o

all: pslse

pslse: $(OBJS)
	$(call Q,CC, $(CC) $(CFLAGS) -o pslse $^ -lpthread -lrt, pslse)

clean:
	rm -f *.[od] pslse

.PHONY: clean all
