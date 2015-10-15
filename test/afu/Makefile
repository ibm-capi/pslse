srcdir = $(PWD)
COMMON_DIR=../../common
include Makefile.vars
include Makefile.rules

OBJS = psl_interface.o utils.o debug.o
CPPOBJS = Descriptor.o AFU.o TagManager.o MachineController.o Machine.o Commands.o

all: afu

afu: $(OBJS) $(CPPOBJS) main.cpp
	$(call Q,CC, g++ $(CFLAGS) -o $@ $^ -lpthread, $@)

clean:
	rm -rf *.[od] *.d-e afu

.PHONY: clean all
