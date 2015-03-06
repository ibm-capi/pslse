srcdir = $(PWD)
include Makefile.vars

OBJS = libcxl.o libcxl_sysfs.o

all: cxl.h libcxl.so libcxl.a

cxl.h:
	$(error 'Please symlink include/uapi/misc/cxl.h from the Linux kernel tree')

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
