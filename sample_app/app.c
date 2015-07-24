/*
 * Copyright 2015 International Business Machines
 */

#include <inttypes.h>
#include <libcxl.h>
#include <stdio.h>

#define CACHELINE_BYTES 128

struct wed {
	uint16_t endian_test;	// Always = 1
	uint16_t volatile status;	// Status bits
	uint32_t reserved00;
	// Reserve entire 128 byte cacheline for WED
	uint64_t reserved01;
	uint64_t reserved02;
	uint64_t reserved03;
	uint64_t reserved04;
	uint64_t reserved05;
	uint64_t reserved06;
	uint64_t reserved07;
	uint64_t reserved08;
	uint64_t reserved09;
	uint64_t reserved10;
	uint64_t reserved11;
	uint64_t reserved12;
	uint64_t reserved13;
	uint64_t reserved14;
	uint64_t reserved15;
};

int main(int argc, char *argv[])
{

	// Open first AFU found
	struct cxl_afu_h *afu_h;
	afu_h = cxl_afu_next(NULL);
	if (!afu_h) {
		fprintf(stderr, "\nNo AFU found!\n\n");
		return -1;
	}
	afu_h = cxl_afu_open_h(afu_h, CXL_VIEW_DEDICATED);
	if (!afu_h) {
		perror("cxl_afu_open_h");
		return -1;
	}
	// Prepare WED
	struct wed *wed = NULL;
	if (posix_memalign((void **)&wed, CACHELINE_BYTES, sizeof(struct wed))) {
		perror("posix_memalign");
		return -1;
	}
	printf("Allocated WED memory @ 0x%016" PRIx64 "\n", (uint64_t) wed);
	wed->endian_test = 1;
	wed->status = 0;

	// Start AFU
	cxl_afu_attach(afu_h, (uint64_t) wed);

	// Map AFU MMIO registers, if needed
	printf("Mapping AFU registers...\n");
	if ((cxl_mmio_map(afu_h, CXL_MMIO_BIG_ENDIAN)) < 0) {
		perror("cxl_mmio_map");
		return -1;
	}

  /**************************************************************************

  Do something here and wait for results.
  
  cxl_mmio_*() functions can only be used here between cxl_mmio_map and
  cxl_mmio_unmap.

  Presumably your application will possibly monitor and/or possibly update
  values in the wed struct or some other place in memory that AFU was
  informed that it could access.  Maybe a bit in the wed struct like those in
  the example "status" field could be updated by the AFU to indicate that
  it has completed a job.  In this example that is why the status field is
  made volatile.  This prevents the compiler from optimization polling of
  the status field.

  **************************************************************************/

	// Unmap AFU MMIO registers, if previously mapped
	cxl_mmio_unmap(afu_h);

	// Free AFU
	cxl_afu_free(afu_h);

	return 0;
}
