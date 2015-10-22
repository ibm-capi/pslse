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
	struct cxl_afu_h *afu_h, *afu_m, *afu_s;
	uint64_t wed, wed_check;
	unsigned seed;
	int opt, option_index, context;
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
	afu_m = NULL;
	if (!afu_h) {
		fprintf(stderr, "FAILED:No AFU found!\n");
		goto done;
	}

	// Open Master AFU
	afu_m = cxl_afu_open_h(afu_h, CXL_VIEW_MASTER);
	if (!afu_m) {
		perror("FAILED:cxl_afu_open_h for master");
		goto done;
	}

	// Generate random 64-bit value for WED
	wed = rand();
	wed <<= 32;
	wed |= rand();

	// Start AFU passing random WED value
	cxl_afu_attach(afu_m, wed);

	// Map AFU MMIO registers for master
	printf("Mapping AFU registers for master...\n");
	if ((cxl_mmio_map(afu_m, CXL_MMIO_BIG_ENDIAN)) < 0) {
		perror("FAILED:cxl_mmio_map for master");
		goto done;
	}

	// Read WED field from AFU
	if (cxl_mmio_read64(afu_m, 0x8, &wed_check)) {
		perror("FAILED:cxl_mmio_read64");
		goto done;
	}

	// Check WED is not populated for directed mode
	if (wed_check == wed) {
		printf("FAILED: WED value found in directed mode!\n");
		goto done;
	}

	printf("WED copy test completed\n");

	// Find first AFU in system
	afu_h = cxl_afu_next(NULL);
	afu_m = NULL;
	if (!afu_h) {
		fprintf(stderr, "FAILED:No AFU found!\n");
		goto done;
	}

	// Open slave AFU
	afu_s = cxl_afu_open_h(afu_h, CXL_VIEW_SLAVE);
	if (!afu_s) {
		perror("FAILED:cxl_afu_open_h for slave");
		goto done;
	}

	// Start AFU passing random WED value
	cxl_afu_attach(afu_s, wed);

	// Map AFU MMIO registers for slave
	printf("Mapping AFU registers for master...\n");
	if ((cxl_mmio_map(afu_s, CXL_MMIO_BIG_ENDIAN)) < 0) {
		perror("FAILED:cxl_mmio_map for slave");
		goto done;
	}

	// Write WED value to slave MMIO space
	if (cxl_mmio_write64(afu_m, 0x7f8, wed)) {
		perror("FAILED:cxl_mmio_read64");
		goto done;
	}

	// Use master to verify slave context
	context = cxl_afu_get_process_element(afu_s);
	printf("Slave context handle = %d\n", context);
	if (cxl_mmio_read64(afu_m, (context * 0x1000) + 0x7f8, &wed_check)) {
		perror("FAILED:cxl_mmio_read64");
		goto done;
	}

	// Check WED is found
	if (wed_check != wed) {
		printf("FAILED: WED value mismatch!\n");
		printf("\tExpected: 0x%016"PRIx64, wed);
		printf("\tActual  : 0x%016"PRIx64, wed_check);
		goto done;
	}

	// Report test as passing
	printf("PASSED\n");
done:
	if (afu_m) {
		// Unmap AFU MMIO registers
		cxl_mmio_unmap(afu_m);
		// Free AFU     
		cxl_afu_free(afu_m);
	}

	return 0;
}
