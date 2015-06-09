srcdir = $(PWD)
COMMON_DIR=../common
include Makefile.vars
include Makefile.rules

OBJS = debug.o libcxl.o psl_interface.o utils.o

all: $(COMMON_DIR)/misc/cxl.h libcxl.so libcxl.a

CHECK_HEADER = $(shell echo \\\#include\ $(1) | $(CC) $(CFLAGS) -E - > /dev/null 2>&1 && echo y || echo n)

$(COMMON_DIR)/misc/cxl.h:
ifeq ($(call CHECK_HEADER,"<misc/cxl.h>"),n)
	$(call Q,WGET $(COMMON_DIR)/misc/cxl.h, wget -P $(COMMON_DIR)/misc -q http://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/plain/include/uapi/misc/cxl.h)
endif

libcxl.so: $(OBJS)
	$(call Q,CC, $(CC) $(CFLAGS) -shared $^ -o $@, $@) -Wl,--version-script symver.map

libcxl.a: $(OBJS)
	$(call Q,AR, $(AR) rcs $@ $^, $@)

clean:
	rm -f *.[od] $(COMMON_DIR)/*.[od] libcxl.so libcxl.a $(COMMON_DIR)/misc/cxl.h

.PHONY: clean all
