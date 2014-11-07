CC := $(CROSS_COMPILE)$(CC)

OBJ_DIR=obj
PSL_DIR=../../psl_interface
VPI_USER_H_DIR= # Directory that contains vpi_user.h

LINK_FLAGS=-shared -E
OBJ_FLAGS=-m32 -Wall -c -DDEBUG
VLI_FLAGS=-m32 -Wall -g -c -fPIC -I$(VPI_USER_H_DIR) -I$(PSL_DIR) -DDEBUG
PSL_FLAGS= $(OBJ_FLAGS) -I$(PSL_DIR)

all: afu_driver.sl

afu_driver.sl: $(OBJ_DIR)/afu_driver.o $(OBJ_DIR)/psl_interface.o
	ld $(LINK_FLAGS) -o afu_driver.sl $^

$(OBJ_DIR)/afu_driver.o: afu_driver.c $(PSL_DIR)/psl_interface.h
	if [ ! -d $(OBJ_DIR) ];then mkdir $(OBJ_DIR);fi
	$(CC) $(VLI_FLAGS) -o $@ afu_driver.c

$(OBJ_DIR)/psl_interface.o: $(PSL_DIR)/psl_interface*
	if [ ! -d $(OBJ_DIR) ];then mkdir $(OBJ_DIR);fi
	$(CC) $(PSL_FLAGS) -o $@ $(PSL_DIR)/psl_interface.c

clean:
	rm -f $(OBJ_DIR)/*.o afu_driver.sl
