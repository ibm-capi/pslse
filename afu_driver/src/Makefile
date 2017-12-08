srcdir = $(PWD)
COMMON_DIR=../../common
include Makefile.vars
include Makefile.rules

OBJS = afu_driver.o psl_interface.o
myString := "afu_driver"
echoString :=  $$LD_LIBRARY_PATH
empty := $(findstring($(myString), $(echoString)))

# if VPI_USER_H_DIR is not set, try to default it to the Cadence install dir path
ifndef VPI_USER_H_DIR
  ifdef CDS_INST_DIR
    VPI_USER_H_DIR=$(CDS_INST_DIR)/tools/include
  endif
endif

# if VPI_USER_H_DIR is still not set, try to use Xilinx install dir path
ifndef VPI_USER_H_DIR
  ifdef XILINX_VIVADO
    VPI_USER_H_DIR=$(XILINX_VIVADO)/data/xsim/include
  endif
endif

# if VPI_USER_H_DIR is STILL not set, print an error message
ifndef VPI_USER_H_DIR
  $(error Must set VPI_USER_H_DIR to point to include path for the simulator)
endif

all: veriuser.sl libdpi.so \
	set_env

set_env:
	$(ifneq($(myString), $(empty)))
		@echo "ALERT!! set the env variable LD_LIBRARY_PATH as mentioned in the QUICK_START guide"
	$(endif)

veriuser.sl libdpi.so : afu_driver.o psl_interface.o
	$(call Q,CC, $(CC) $(LINK_FLAGS) -o $@ $^, $@)

afu_driver.o: CFLAGS += -I$(VPI_USER_H_DIR) -I$(COMMON_DIR)

clean:
	rm -f *.[od] veriuser.sl libdpi.so
