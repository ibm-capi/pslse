srcdir = $(PWD)
include Makefile.vars
include Makefile.rules

OBJS = afu_driver.o $(COMMON_DIR)/psl_interface.o
COMMON_DIR=../../common

ifdef CDS_INST_DIR
  VPI_USER_H_DIR=$(CDS_INST_DIR)/tools/include
endif

ifndef VPI_USER_H_DIR
$(error Must set VPI_USER_H_DIR to point to include path for the simulator)
endif

all: veriuser.sl libvpi.so

veriuser.sl : afu_driver.o $(COMMON_DIR)/psl_interface.o
	$(call Q,LD, ld $(LINK_FLAGS) -o $@ $^, veriuser.sl)

libvpi.so : afu_driver.o $(COMMON_DIR)/psl_interface.o
	$(call Q,LD, ld $(LINK_FLAGS) -o $@ $^, libvpi.so)

afu_driver.o: CFLAGS += -fPIC -I$(VPI_USER_H_DIR) -I$(COMMON_DIR)

$(COMMON_DIR)/psl_interface.o: CFLAGS += -fPIC

clean:
	rm -f *.[od] $(COMMON_DIR)/*.[od] veriuser.sl libvpi.so
