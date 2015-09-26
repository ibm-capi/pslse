/*
 * Copyright 2015 International Business Machines
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* Description : mmio.c
 *
 * This test performs basic mmio test using the Test AFU for validating pslse
 */

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "libcxl.h"

int main(int argc, char *argv[])
{
	struct cxl_afu_h *afu_h;
	uint64_t wed, wed_check, rand64, rand64_check;
	uint32_t rand32_upper, rand32_lower;

	///////////////////////
	// Initial AFU setup //
	///////////////////////

	// Seed random number generator
	srand(time(NULL));

	// Find first AFU in system
	afu_h = cxl_afu_next(NULL);
	if (!afu_h) {
		fprintf(stderr, "FAILED:No AFU found!\n");
		return -1;
	}

	// Open AFU
	afu_h = cxl_afu_open_h(afu_h, CXL_VIEW_DEDICATED);
	if (!afu_h) {
		perror("FAILED:cxl_afu_open_h");
		return -1;
	}

	// Generate random 64-bit value for WED
	wed = rand();
	wed <<= 32;
	wed |= rand();

	// Start AFU passing random WED value
	cxl_afu_attach(afu_h, wed);

	// Map AFU MMIO registers
	printf("Mapping AFU registers...\n");
	if ((cxl_mmio_map(afu_h, CXL_MMIO_BIG_ENDIAN)) < 0) {
		perror("FAILED:cxl_mmio_map");
		return -1;
	}

	/////////////////////////////////////////////////////
	// CHECK 1 - WED value was passed to AFU correctly //
	/////////////////////////////////////////////////////

	// Read WED from AFU and verify
	if (cxl_mmio_read64(afu_h, 0x8, &wed_check)) {
		perror("FAILED:cxl_mmio_read64");
		return -1;
	}
	if (wed != wed_check) {
		printf("\nFAILED:WED mismatch!\n");
		printf("\tExpected:0x%016"PRIx64"\n", wed);
		printf("\tActual  :0x%016"PRIx64"\n", wed_check);
		return -1;
	}
	printf("WED check complete\n");

	//////////////////////////////////////////////////////////////
	// CHECK 2 - Write 64-bit value and check with 32-bit reads //
	//////////////////////////////////////////////////////////////

	// Write random 64-bit value to MMIO space
	rand64 = rand();
	rand64 <<= 32;
	rand64 |= rand();
	if (cxl_mmio_write64(afu_h, 0x17f0, rand64)) {
		perror("FAILED:cxl_mmio_write64");
		return -1;
	}

	// Use two 32-bit read to check 64-bit value written
	cxl_mmio_read32(afu_h, 0x17f0, &rand32_upper);
	cxl_mmio_read32(afu_h, 0x17f4, &rand32_lower);
	rand64_check = (uint64_t) rand32_upper;
	rand64_check <<= 32;
	rand64_check |= (uint64_t) rand32_lower;
	if (rand64 != rand64_check) {
		printf("\nFAILED:64-bit write => 32-bit reads mismatch!\n");
		printf("\tExpected:0x%016"PRIx64"\n", rand64);
		printf("\tActual  :0x%016"PRIx64"\n", rand64_check);
		return -1;
	}
	printf("64-bit write => 32-bit reads check complete\n");

	//////////////////////////////////////////////////////////////
	// CHECK 3 - Write 32-bit values and check with 64-bit read //
	//////////////////////////////////////////////////////////////

	// Write two random 32-bit values to a single 64-bit MMIO register
	rand32_upper = rand();
	if (cxl_mmio_write32(afu_h, 0x17f8, rand32_upper)) {
		perror("FAILED:cxl_mmio_write32");
		return -1;
	}
	rand32_lower = rand();
	if (cxl_mmio_write32(afu_h, 0x17fc, rand32_lower)) {
		perror("FAILED:cxl_mmio_write32");
		return -1;
	}

	// Build 64-bit value from two 32-bit values
	rand64 = (uint64_t) rand32_upper;
	rand64 <<= 32;
	rand64 |= (uint64_t) rand32_lower;

	// Check 32-bit writes with one 64-bit read
	cxl_mmio_read64(afu_h, 0x17f8, &rand64_check);
	if (rand64 != rand64_check) {
		printf("\nFAILED:32-bit writes => 64-bit read mismatch!\n");
		printf("\tExpected:0x%016"PRIx64"\n", rand64);
		printf("\tActual  :0x%016"PRIx64"\n", rand64_check);
		return -1;
	}
	printf("32-bit writes => 64-bit read check complete\n");

	////////////////////
	// Close out test //
	////////////////////

	// Unmap AFU MMIO registers
	cxl_mmio_unmap(afu_h);

	// Free AFU     
	cxl_afu_free(afu_h);

	// Report test as passing
	printf("PASSED\n");
	return 0;
}
