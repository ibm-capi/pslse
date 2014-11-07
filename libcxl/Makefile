srcdir = $(PWD)
include Makefile.vars

OBJS = libcxl.o libcxl_sysfs.o

all: libcxl.so libcxl.a

cxl.h:
	$(error 'Please symlink include/uapi/misc/cxl.h from the Linux kernel tree')

libcxl.o libcxl_sysfs.o : CFLAGS += -fPIC

libcxl.so: libcxl.o libcxl_sysfs.o
	$(CC) $(CFLAGS) -shared libcxl.o libcxl_sysfs.o -o libcxl.so

libcxl.a: libcxl.o libcxl_sysfs.o
	ar rcs libcxl.a libcxl.o libcxl_sysfs.o

include Makefile.rules

clean:
	rm -f *.o *.d libcxl.so libcxl.a

.PHONY: clean all
