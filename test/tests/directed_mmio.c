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
	struct cxl_afu_h *afu_h, *afu_m;
	uint64_t wed, wed_check;
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
	afu_m = NULL;
	if (!afu_h) {
		fprintf(stderr, "FAILED:No AFU found!\n");
		goto done;
	}

	// Open Master AFU
	afu_m = cxl_afu_open_h(afu_h, CXL_VIEW_MASTER);
	if (!afu_m) {
		perror("FAILED:cxl_afu_open_h");
		goto done;
	}

	// Generate random 64-bit value for WED
	wed = rand();
	wed <<= 32;
	wed |= rand();

	// Start AFU passing random WED value
	cxl_afu_attach(afu_m, wed);

	// Map AFU MMIO registers
	printf("Mapping AFU registers...\n");
	if ((cxl_mmio_map(afu_m, CXL_MMIO_BIG_ENDIAN)) < 0) {
		perror("FAILED:cxl_mmio_map");
		goto done;
	}

	// Read WED from AFU and verify
	if (cxl_mmio_read64(afu_m, 0x8, &wed_check)) {
		perror("FAILED:cxl_mmio_read64");
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
