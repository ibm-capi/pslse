srcdir = $(PWD)
include Makefile.vars
include Makefile.rules

OBJS = libcxl.o psl_interface.o
CFLAGS += -Iinclude -fPIC

all: include/misc/cxl.h libcxl.so libcxl.a

CHECK_HEADER = $(shell echo \\\#include\ $(1) | $(CC) $(CFLAGS) -E - > /dev/null 2>&1 && echo y || echo n)

include/misc/cxl.h:
ifeq ($(call CHECK_HEADER,"<misc/cxl.h>"),n)
	$(call Q,WGET include/misc/cxl.h, wget -P include/misc -q http://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/plain/include/uapi/misc/cxl.h)
endif

libcxl.so: libcxl.o psl_interface.o
	$(call Q,CC, $(CC) $(CFLAGS) -shared libcxl.o psl_interface.o -o libcxl.so, libcxl.so) -Wl,--version-script symver.map

libcxl.a: libcxl.o psl_interface.o
	$(call Q,AR, ar rcs libcxl.a libcxl.o psl_interface.o, libcxl.a)

libcxl.o psl_interface.o:

clean:
	rm -f *.o *.d libcxl.so libcxl.a include/misc/cxl.h

.PHONY: clean all
