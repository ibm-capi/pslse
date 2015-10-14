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

/* Description : bad_align.c
 *
 * This test performs memcopy but uses a bad address alignment for the write
 */

#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "libcxl.h"
#include "psl_interface_t.h"
#include "TestAFU_config.h"
#include "utils.h"

void usage(char *name)
{
	printf("Usage: %s [OPTION]...\n\n", name);
	printf("  -s, --seed\t\tseed for random number generation\n");
	printf("      --help\tdisplay this help and exit\n\n");
}

int main(int argc, char *argv[])
{
	MachineConfig machine;
	char *cacheline0, *cacheline1, *name;
	uint64_t wed, addr;
	unsigned seed;
	int i, opt, option_index;
	uint16_t size;
	uint8_t response;

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

	// Allocate aligned memory for both cachelines
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
	if ((response = config_enable_and_run_machine(afu_h, &machine, 1, 0, PSL_COMMAND_READ_CL_NA, CACHELINE_BYTES, 0, 0, (uint64_t)cacheline0, CACHELINE_BYTES)) < 0)
	{
		printf("FAILED:config_enable_and_run_machine");
		goto done;
	}

	// Check for valid response
	if (response != PSL_RESPONSE_DONE)
	{
		printf("FAILED: Unexpected response code 0x%x\n", response);
		goto done;
	}

	printf("Completed cacheline read\n");

	// Generate bad command address
	addr = (uint64_t) cacheline1;
	size = 0x2 << (rand() % 6);
	addr += rand() % size;

	// Use AFU Machine 1 to write the data to the second cacheline
	printf("Address: 0x%016"PRIx64" Size: 0x%02x\n", addr, size);
	if ((response = config_enable_and_run_machine(afu_h, &machine, 1, 0,
						      PSL_COMMAND_WRITE_NA,
						      size, 0, 0, addr,
						      size)) < 0)
	{
		printf("FAILED:config_enable_and_run_machine");
		goto done;
	}

	// Check for valid response
	if (response != PSL_RESPONSE_FAILED)
	{
		printf("FAILED: Unexpected response code 0x%x\n", response);
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
