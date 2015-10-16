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

#include <getopt.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "libcxl.h"

void usage(char *name)
{
	printf("Usage: %s [OPTION]...\n\n", name);
	printf("  -s, --seed\t\tseed for random number generation\n");
	printf("      --help\tdisplay this help and exit\n\n");
}

int main(int argc, char *argv[])
{
	struct cxl_afu_h *afu_h;
	uint64_t wed, wed_check, rand64, rand64_check;
	uint32_t rand32_upper, rand32_lower;
	unsigned seed;
	int opt, option_index;
	char *name;

	name = strrchr(argv[0], '/');
	if (name)
		name++;
	else
		name = argv[0];

	static struct option long_options[] = {
		{"help",	no_argument,		0,		'h'},
		{"seed",	required_argument,	0,		's'},
		{NULL, 0, 0, 0}
	};

	option_index = 0;
	seed = time(NULL);
	while ((opt = getopt_long (argc, argv, "hs:",
				   long_options, &option_index)) >= 0) {
		switch (opt)
		{
		case 0:
			break;
		case 's':
			seed = strtoul(optarg, NULL, 0);
			break;
		case 'h':
		default:
			usage(name);
			return 0;
		}
	}

	// Seed random number generator
	srand(seed);
	printf("%s: seed=%d\n", name, seed);

	// Find first AFU in system
	afu_h = cxl_afu_next(NULL);
	if (!afu_h) {
		fprintf(stderr, "FAILED:No AFU found!\n");
		goto done;
	}

	// Open AFU
	afu_h = cxl_afu_open_h(afu_h, CXL_VIEW_DEDICATED);
	if (!afu_h) {
		perror("FAILED:cxl_afu_open_h");
		goto done;
	}

	printf("Attempt mapping AFU registers before attach\n");
	if ((cxl_mmio_map(afu_h, CXL_MMIO_BIG_ENDIAN)) == 0) {
		printf("FAILED:cxl_mmio_map");
		goto done;
	}

	printf("Attempt mmio read before successful mapping\n");
	if (cxl_mmio_read64(afu_h, 0x8, &wed_check) == 0) {
		printf("FAILED:cxl_mmio_read64");
		goto done;
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
		goto done;
	}

	/////////////////////////////////////////////////////
	// CHECK 1 - WED value was passed to AFU correctly //
	/////////////////////////////////////////////////////

	// Read WED from AFU and verify
	if (cxl_mmio_read64(afu_h, 0x8, &wed_check) < 0) {
		perror("FAILED:cxl_mmio_read64");
		goto done;
	}
	if (wed != wed_check) {
		printf("\nFAILED:WED mismatch!\n");
		printf("\tExpected:0x%016"PRIx64"\n", wed);
		printf("\tActual  :0x%016"PRIx64"\n", wed_check);
		goto done;
	}
	printf("WED check complete\n");

	//////////////////////////////////////////////////////////////
	// CHECK 2 - Write 64-bit value and check with 32-bit reads //
	//////////////////////////////////////////////////////////////

	// Write random 64-bit value to MMIO space
	rand64 = rand();
	rand64 <<= 32;
	rand64 |= rand();
	if (cxl_mmio_write64(afu_h, 0x17f0, rand64) < 0) {
		perror("FAILED:cxl_mmio_write64");
		goto done;
	}

	// Use two 32-bit read to check 64-bit value written
	if (cxl_mmio_read32(afu_h, 0x17f0, &rand32_upper) < 0) {
		perror("FAILED:cxl_mmio_read32");
		goto done;
	}
	if (cxl_mmio_read32(afu_h, 0x17f4, &rand32_lower) < 0) {
		perror("FAILED:cxl_mmio_read32");
		goto done;
	}
	rand64_check = (uint64_t) rand32_upper;
	rand64_check <<= 32;
	rand64_check |= (uint64_t) rand32_lower;
	if (rand64 != rand64_check) {
		printf("\nFAILED:64-bit write => 32-bit reads mismatch!\n");
		printf("\tExpected:0x%016"PRIx64"\n", rand64);
		printf("\tActual  :0x%016"PRIx64"\n", rand64_check);
		goto done;
	}
	printf("64-bit write => 32-bit reads check complete\n");

	//////////////////////////////////////////////////////////////
	// CHECK 3 - Write 32-bit values and check with 64-bit read //
	//////////////////////////////////////////////////////////////

	// Write two random 32-bit values to a single 64-bit MMIO register
	rand32_upper = rand();
	if (cxl_mmio_write32(afu_h, 0x17f8, rand32_upper) < 0) {
		perror("FAILED:cxl_mmio_write32");
		goto done;
	}
	rand32_lower = rand();
	if (cxl_mmio_write32(afu_h, 0x17fc, rand32_lower) < 0) {
		perror("FAILED:cxl_mmio_write32");
		goto done;
	}

	// Build 64-bit value from two 32-bit values
	rand64 = (uint64_t) rand32_upper;
	rand64 <<= 32;
	rand64 |= (uint64_t) rand32_lower;

	// Check 32-bit writes with one 64-bit read
	if (cxl_mmio_read64(afu_h, 0x17f8, &rand64_check) < 0) {
		perror("FAILED:cxl_mmio_read64");
		goto done;
	}
	if (rand64 != rand64_check) {
		printf("\nFAILED:32-bit writes => 64-bit read mismatch!\n");
		printf("\tExpected:0x%016"PRIx64"\n", rand64);
		printf("\tActual  :0x%016"PRIx64"\n", rand64_check);
		goto done;
	}
	printf("32-bit writes => 64-bit read check complete\n");

	// Report test as passing
	printf("PASSED\n");
done:
	if (afu_h) {
		// Unmap AFU MMIO registers
		cxl_mmio_unmap(afu_h);
		// Free AFU     
		cxl_afu_free(afu_h);
	}

	return 0;
}
