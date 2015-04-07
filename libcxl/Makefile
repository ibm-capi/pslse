# (c) Copyright International Business Machines 2014

OBJ_DIR=obj
PSL_DIR=./psl_interface

CFLAGS += -O2 -Wall -m64
LIBCFLAGS += -O2 -Wall -m64
#CFLAGS += -g -Wall -m64
#LIBCFLAGS += -g -Wall -m64 -DDEBUG
PSL_FLAGS= $(LIBCFLAGS) -I$(PSL_DIR)

all: cxl.h libcxl.a

cxl.h:
	$(error 'Please symlink include/uapi/misc/cxl.h from the Linux kernel tree')

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
