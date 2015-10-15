srcdir = $(PWD)
COMMON_DIR=../common
include Makefile.vars
include Makefile.rules

OBJS = libcxl.o debug.o utils.o

#all: $(COMMON_DIR)/misc/cxl.h libcxl.so libcxl.a
all: $(COMMON_DIR)/misc/cxl.h libcxl.a

CHECK_HEADER = $(shell echo \\\#include\ $(1) | $(CC) $(CFLAGS) -E - > /dev/null 2>&1 && echo y || echo n)

$(COMMON_DIR)/misc/cxl.h:
ifeq ($(call CHECK_HEADER,"<misc/cxl.h>"),n)
	$(call Q,CURL $(COMMON_DIR)/misc/cxl.h, mkdir $(COMMON_DIR)/misc 2>/dev/null; curl -o $(COMMON_DIR)/misc/cxl.h -s http://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/plain/include/uapi/misc/cxl.h)
endif

#libcxl.so: $(OBJS)
#	$(call Q,CC, $(CC) $(CFLAGS) -shared $^ -o $@, $@) -Wl,--version-script symver.map

libcxl.a: $(OBJS)
	$(call Q,AR, $(AR) rcs $@ $^, $@)

clean:
	rm -f *.[od] $(COMMON_DIR)/*.[od] gmon.out libcxl.so libcxl.a $(COMMON_DIR)/misc/cxl.h

.PHONY: clean all
