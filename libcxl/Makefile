srcdir = $(PWD)
include Makefile.vars

OBJS = libcxl.o libcxl_sysfs.o

all: cxl.h libcxl.so libcxl.a

CHECK_HEADER = $(shell echo -e \\\#include $(1) | \
                 $(CC) $(CPPFLAGS) -E - 2>&1 > /dev/null || echo fail)

ifeq ($(call CHECK_HEADER,"<misc/cxl.h>"),)
  PSL_FLAGS += -DHAVE_MISC_CXL_H
else ifneq ($(call CHECK_HEADER,'"cxl.h"'),)
  $(error 'Please symlink include/uapi/misc/cxl.h from the Linux kernel tree')
endif

libcxl.o libcxl_sysfs.o : CFLAGS += -fPIC

libcxl.so: libcxl.o libcxl_sysfs.o
	$(call Q,CC, $(CC) $(CFLAGS) -shared libcxl.o libcxl_sysfs.o -o libcxl.so, libcxl.so)

libcxl.a: libcxl.o libcxl_sysfs.o
	$(call Q,AR, ar rcs libcxl.a libcxl.o libcxl_sysfs.o, libcxl.a)

include Makefile.rules

clean:
	rm -f *.o *.d libcxl.so libcxl.a
	$(MAKE) -C clean

.PHONY: clean all
