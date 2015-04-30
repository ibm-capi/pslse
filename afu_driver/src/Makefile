srcdir = $(PWD)
COMMON_DIR=../../common
include Makefile.vars
include Makefile.rules

OBJS = afu_driver.o psl_interface.o

ifdef CDS_INST_DIR
  VPI_USER_H_DIR=$(CDS_INST_DIR)/tools/include
endif

ifndef VPI_USER_H_DIR
$(error Must set VPI_USER_H_DIR to point to include path for the simulator)
endif

all: veriuser.sl libvpi.so

veriuser.sl : afu_driver.o psl_interface.o
	$(call Q,LD, $(LD) $(LINK_FLAGS) -o $@ $^, veriuser.sl)

libvpi.so : afu_driver.o psl_interface.o
	$(call Q,LD, $(LD) $(LINK_FLAGS) -o $@ $^, libvpi.so)

afu_driver.o: CFLAGS += -I$(VPI_USER_H_DIR) -I$(COMMON_DIR)

clean:
	rm -f *.[od] veriuser.sl libvpi.so
