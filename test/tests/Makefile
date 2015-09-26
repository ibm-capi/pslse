srcdir = $(PWD)
COMMON_DIR=../../common
LIBCXL_DIR=../../libcxl
include Makefile.vars
include Makefile.rules

SRCS=$(wildcard *.c)
OBJS=$(subst .c,.o,$(SRCS)) TestAFU_config.o
TESTS=$(subst .c,,$(SRCS))
DEPS=TestAFU_config.o $(LIBCXL_DIR)/libcxl.a

all: misc/cxl.h $(TESTS)

CHECK_HEADER = $(shell echo \\\#include\ $(1) | $(CC) $(CFLAGS) -E - > /dev/null 2>&1 && echo y || echo n)

misc/cxl.h:
ifeq ($(call CHECK_HEADER,"<misc/cxl.h>"),n)
	$(call Q,CURL $(COMMON_DIR)/misc/cxl.h, mkdir $(COMMON_DIR)/misc 2>/dev/null; curl -o $(COMMON_DIR)/misc/cxl.h -s http://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/plain/include/uapi/misc/cxl.h)
endif

.SECONDEXPANSION:

$(TESTS) : $(addsuffix .o,$$@) $(DEPS)
	$(call Q,CC, $(CC) $^ -I$(COMMON_DIR) -I$(LIBCXL_DIR) -o $@ -lpthread, $@)

TesetAFU_config.o :

clean:
	rm -f *.o *.d gmon.out $(TESTS)
