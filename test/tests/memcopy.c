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

/* Description : memcopy.c
 *
 * This test performs memcopy using the Test AFU for validating pslse
 */

#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "libcxl.h"
#include "TestAFU_config.h"

#define CACHELINE_BYTES 128
#define READ_CL_NA 0x0A00
#define WRITE_NA   0x0D00

void usage(char *name)
{
	printf("Usage: %s [OPTION]...\n\n", name);
	printf("  -s, --seed\t\tseed for random number generation\n");
	printf("      --help\tdisplay this help and exit\n\n");
}

int main(int argc, char *argv[])
{
	MachineConfig machine;
	char *cacheline0, *cacheline1;
	uint64_t wed;
	int i, quadrant, byte;
	uint8_t response;
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

	// Open first AFU found
	struct cxl_afu_h *afu_h;
	afu_h = cxl_afu_next(NULL);
	if (!afu_h) {
		fprintf(stderr, "\nNo AFU found!\n\n");
		goto done;
	}
	afu_h = cxl_afu_open_h(afu_h, CXL_VIEW_DEDICATED);
	if (!afu_h) {
		perror("cxl_afu_open_h");
		goto done;
	}

	// Set WED to random value
	wed = rand();
	wed <<= 32;
	wed |= rand();
	// Start AFU
	cxl_afu_attach(afu_h, wed);

	// Map AFU MMIO registers
	printf("Mapping AFU registers...\n");
	if ((cxl_mmio_map(afu_h, CXL_MMIO_BIG_ENDIAN)) < 0) {
		perror("cxl_mmio_map");
		goto done;

	}

	// Allocate aligned memory for two cachelines
	if (posix_memalign((void **)&cacheline0, CACHELINE_BYTES, CACHELINE_BYTES) != 0) {
		perror("FAILED:posix_memalign");
		goto done;
	}
	if (posix_memalign((void **)&cacheline1, CACHELINE_BYTES, CACHELINE_BYTES) != 0) {
		perror("FAILED:posix_memalign");
		goto done;
	}

	// Pollute first cacheline with random values
	for (i = 0; i < CACHELINE_BYTES; i++)
		cacheline0[i] = rand();

	// Use AFU Machine 1 to read the first cacheline from memory to AFU
	if ((response = config_enable_and_run_machine(afu_h, &machine, 1, 0, READ_CL_NA, CACHELINE_BYTES, 0, 0, (uint64_t)cacheline0, CACHELINE_BYTES)) < 0)
	{
		printf("FAILED:config_enable_and_run_machine");
		goto done;
	}

	// Check for valid response
	if (response != 0)
	{
		printf("FAILED: Unexpected response code 0x%x\n", response);
		goto done;
	}

	printf("Completed the first cacheline read and got the random data\n");

	// Use AFU Machine 1 to write the data to the second cacheline
	if ((response = config_enable_and_run_machine(afu_h, &machine, 1, 0, WRITE_NA, CACHELINE_BYTES, 0, 0, (uint64_t)cacheline1, CACHELINE_BYTES)) < 0)
	{
		printf("FAILED:config_enable_and_run_machine");
		goto done;
	}

	// Check for valid response
	if (response != 0)
	{
		printf("FAILED: Unexpected response code 0x%x\n", response);
		goto done;
	}

	// Test if copy from cacheline0 to cacheline1 was successful
	if (memcmp(cacheline0,cacheline1, CACHELINE_BYTES) != 0) {
		printf("FAILED:memcmp\n");
		for (quadrant = 0; quadrant < 4; quadrant++) {
			printf("DEBUG: Expected  Q%d 0x", quadrant);
			for (byte = 0; byte < CACHELINE_BYTES /4; byte++) {
				printf("%02x", cacheline0[byte+(quadrant*32)]);
			}
			printf("\n");
		}
		for (quadrant = 0; quadrant < 4; quadrant++) {
			printf("DEBUG: Actual  Q%d 0x", quadrant);
			for (byte = 0; byte < CACHELINE_BYTES / 4; byte++) {
				printf("%02x", cacheline1[byte+(quadrant*32)]);
			}
			printf("\n");
		}
		goto done;
	}

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
