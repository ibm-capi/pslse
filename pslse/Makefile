# (c) Copyright International Business Machines 2014

OBJ_DIR=obj
PSL_DIR=./psl_interface

CFLAGS += -O2 -Wall -m64
LIBCFLAGS += -O2 -Wall -m64
#CFLAGS += -g -Wall -m64
#LIBCFLAGS += -g -Wall -m64 -DDEBUG
PSL_FLAGS= $(LIBCFLAGS) -I$(PSL_DIR)

CHECK_HEADER = $(shell echo -e \\\#include $(1) | \
	         $(CC) $(CPPFLAGS) -E - 2>&1 > /dev/null || echo fail)

ifeq ($(call CHECK_HEADER,"<misc/cxl.h>"),)
  PSL_FLAGS += -DHAVE_MISC_CXL_H
else ifneq ($(call CHECK_HEADER,'"cxl.h"'),)
  $(error 'Please symlink include/uapi/misc/cxl.h from the Linux kernel tree')
endif

all: libcxl.a

libcxl.a: $(OBJ_DIR)/libcxl.o $(OBJ_DIR)/psl_interface.o
	ar rcs $@ $^

$(OBJ_DIR)/libcxl.o: libcxl.c libcxl.h
	if [ ! -d $(OBJ_DIR) ];then mkdir $(OBJ_DIR);fi
	$(CC) $(PSL_FLAGS) -fPIC -c libcxl.c -o $@

$(OBJ_DIR)/psl_interface.o: $(PSL_DIR)/psl_interface*
	if [ ! -d $(OBJ_DIR) ];then mkdir $(OBJ_DIR);fi
	$(CC) $(PSL_FLAGS) -fPIC -c $(PSL_DIR)/psl_interface.c -o $@

clean:
	/bin/rm -f $(APP) *.a $(OBJ_DIR)/*.o
