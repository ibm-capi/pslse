CC := $(CROSS_COMPILE)$(CC)

OBJ_DIR=obj
PSL_DIR=../../psl_interface
LINK_FLAGS=-shared -E
PSL_FLAGS=-Wall -c -DDEBUG -I$(PSL_DIR)
VLI_FLAGS=-Wall -g -c -fPIC -I$(VPI_USER_H_DIR) -I$(PSL_DIR) -DDEBUG

ifdef CDS_INST_DIR
  VPI_USER_H_DIR=$(CDS_INST_DIR)/tools/include
else
  ## NOTE: If using 32-bit VPI functions, must link as 32bit below;
  ## may require downloading 32b C libs which are not
  ## installed by default on some Linux distributions
  ## (eg. Debian need to do sudo dpkg --add-architecture i386; sudo apt-get install libc6:i386; )
  ifeq ($(shell uname) $(shell arch),Linux x86_64)
    LINK_FLAGS+=-melf_i386
    PSL_FLAGS+=-m32
    VLI_FLAGS+=-m32
  endif
endif

ifndef VPI_USER_H_DIR
$(error Must set VPI_USER_H_DIR to point to include path for the simulator)
endif

all: afu_driver.sl libvpi.so

libvpi.so afu_driver.sl: $(OBJ_DIR)/afu_driver.o $(OBJ_DIR)/psl_interface.o
	ld $(LINK_FLAGS) -o $@ $^

$(OBJ_DIR)/afu_driver.o: afu_driver.c $(PSL_DIR)/psl_interface.h
	if [ ! -d $(OBJ_DIR) ];then mkdir $(OBJ_DIR);fi
	$(CC) $(VLI_FLAGS) -o $@ afu_driver.c

$(OBJ_DIR)/psl_interface.o: $(PSL_DIR)/psl_interface*
	if [ ! -d $(OBJ_DIR) ];then mkdir $(OBJ_DIR);fi
	$(CC) $(PSL_FLAGS) -o $@ $(PSL_DIR)/psl_interface.c

clean:
	rm -f $(OBJ_DIR)/*.o afu_driver.sl libvpi.so
