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
	uint64_t wed;
	unsigned seed;
	int i, quadrant, byte, opt, option_index;
	int response;
	int context, machine_number;

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

	// find first AFU found
	struct cxl_afu_h *afu_h, *afu_m, *afu_s;
	afu_m = afu_s = NULL;
	
        afu_h = cxl_afu_next(NULL);
	if (!afu_h) {
		fprintf(stderr, "\nNo AFU found!\n\n");
		goto done;
	}
	
        
        // afu master 
	afu_m = cxl_afu_open_h(afu_h, CXL_VIEW_MASTER);
	if (!afu_m) {
		perror("cxl_afu_open_h for master");
		goto done;
	}

	// Set WED to random value
	wed = rand();
	wed <<= 32;
	wed |= rand();

	// Start AFU for master
	printf("Attach AFU master\n");
	if (cxl_afu_attach(afu_m, wed) < 0) {
            perror("FAILED:cxl_afu_attach for master");
		goto done;
        }

	printf("wed = 0x%"PRIx64"\n", wed);

	// Map AFU MMIO registers
	printf("Mapping AFU master registers...\n");
	if ((cxl_mmio_map(afu_m, CXL_MMIO_BIG_ENDIAN)) < 0) {
		perror("cxl_mmio_map for master");
		goto done;

	}
	printf("End AFU master mmio map\n");

	context = cxl_afu_get_process_element(afu_m);

	printf("Master context = %d\n", context);
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
	{
		cacheline0[i] = rand();
		//printf("cacheline0[%d] = 0x%x\n", i, cacheline0[i]);
	}

	// Initialize machine configuration
	printf("initialize machine\n");
	init_machine(&machine);
	printf("End init machine\n");

	// Use AFU Machine 0 to read the first cacheline from memory to AFU
	printf("Configure, enable and run machine\n");
	if ((response = config_enable_and_run_machine(afu_m, &machine, 0, context, PSL_COMMAND_XLAT_RD_P0, CACHELINE_BYTES, 0, 0, (uint64_t)cacheline0, CACHELINE_BYTES, DIRECTED_M)) < 0)
	{
		printf("FAILED:config_enable_and_run_machine for master XLAT_RD response = %d\n", response);
		goto done;
	}
	printf("End configure enable and run machine for XLAT_RD\n");
	// Check for valid response
	if (response != PSL_RESPONSE_DONE)
	{
		printf("FAILED: Unexpected response code 0x%x\n", response);
		goto done;
	}

	printf("Completed cacheline read\n");

	// Use AFU Machine 0 to write the data to the second cacheline
	if ((response = config_enable_and_run_machine(afu_m, &machine, 0, context, PSL_COMMAND_XLAT_WR_P0, CACHELINE_BYTES, 0, 0, (uint64_t)cacheline1, CACHELINE_BYTES, DIRECTED_M)) < 0)
	{
		printf("FAILED:config_enable_and_run_machine for master XLAT_WR response = %d\n", response);
		goto done;
	}
	printf("End configure enable and run machine for XLAT WR\n");
	// Check for valid response
	if (response != PSL_RESPONSE_DONE)
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

	printf("Master AFU: PASSED\n");
        
        // afu slave
        // find next afu
        afu_h = cxl_afu_next(NULL);
	if (!afu_h) {
		fprintf(stderr, "\nNo AFU found!\n\n");
		goto done;
	}
	afu_s = cxl_afu_open_h(afu_h, CXL_VIEW_SLAVE);
	if (!afu_s) {
		perror("cxl_afu_open_h for slave");
		goto done;
	}

	// Set WED to random value
	wed = rand();
	wed <<= 32;
	wed |= rand();
	// Start AFU for slave
	if (cxl_afu_attach(afu_s, wed) < 0) {
            perror("FAILED:cxl_afu_attach for slave");
		goto done;
        }

	// Map AFU MMIO registers
	printf("Mapping AFU slave registers...\n");
	if ((cxl_mmio_map(afu_s, CXL_MMIO_BIG_ENDIAN)) < 0) {
		perror("cxl_mmio_map for slave");
		goto done;
	}
	printf("End AFU slave mmio map\n");

	context = cxl_afu_get_process_element(afu_s);
	printf("Slave context = %d\n", context);

	machine_number = 20;

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

	// Initialize machine configuration
	//init_machine(&machine);

	// Use AFU Machine 1 to read the first cacheline from memory to AFU
	printf("Start config enable and run machine for slave\n");
	if ((response = config_enable_and_run_machine(afu_s, &machine, machine_number, context, PSL_COMMAND_XLAT_RD_P0, CACHELINE_BYTES, 0, 0, (uint64_t)cacheline0, CACHELINE_BYTES, DIRECTED)) < 0)
	{
		printf("FAILED:config_enable_and_run_machine for slave");
		goto done;
	}
	printf("End config enable and run machine for slave\n");
	// Check for valid response
	if (response != PSL_RESPONSE_DONE)
	{
		printf("FAILED: Unexpected response code 0x%x\n", response);
		goto done;
	}

	printf("Completed cacheline read for slave\n");

	// Use AFU Machine 1 to write the data to the second cacheline
	if ((response = config_enable_and_run_machine(afu_s, &machine, machine_number, context, PSL_COMMAND_XLAT_WR_P0, CACHELINE_BYTES, 0, 0, (uint64_t)cacheline1, CACHELINE_BYTES, DIRECTED)) < 0)
	{
		printf("FAILED:config_enable_and_run_machine for slave");
		goto done;
	}

	// Check for valid response
	if (response != PSL_RESPONSE_DONE)
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

	printf("Slave AFU: PASSED\n");
        
done:
        // unmap and free slave afu 
        if (afu_s) {
            cxl_mmio_unmap(afu_s);
            cxl_afu_free(afu_s);
        }
        // unmap and free master afu
	if (afu_m) {
		// Unmap AFU MMIO registers
		cxl_mmio_unmap(afu_m);

		// Free AFU
		cxl_afu_free(afu_m);
	}
       

	return 0;
}
