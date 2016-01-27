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

/* Description : mem_commands.c
 *
 * This test causes the AFU to randomly drive almost all pslse supported command
 * memory access types.
 */

#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "libcxl.h"
#include "libcxl_internal.h"
#include "psl_interface_t.h"
#include "TestAFU_config.h"
#include "utils.h"

void usage(char *name)
{
	printf("Usage: %s [OPTION]...\n\n", name);
	printf("  -s, --seed  [SEED]   \tseed for random number generation\n");
	printf("      --help\tdisplay this help and exit\n\n");
}

void stop_afu(struct cxl_afu_h *afu_h)
{
	if (afu_h) {
		// Unmap AFU MMIO registers
		if(cxl_mmio_unmap(afu_h) < 0) {
			printf("FAILED: cxl_mmio_unmap\n");
			exit(-1);
		}

		// Free AFU
		cxl_afu_free(afu_h);
	}
}

struct cxl_afu_h *start_test(struct cxl_afu_h *afu_h, MachineConfig *machine, char *area)
{
	uint16_t command;
	int i;

	printf("Enabling AFU machine for random read/write commands\n");
	// Have each AFU Machine read or write repeatedly to memory area
	set_machine_config_enable_always(machine);
	for (i = 0; i < 64; i++) {
		switch (rand() % 15) {
		case 1:
			command = PSL_COMMAND_READ_CL_NA;
			break;
		case 2:
			command = PSL_COMMAND_READ_CL_S;
			break;
		case 3:
			command = PSL_COMMAND_READ_CL_M;
			break;
		case 4:
			command = PSL_COMMAND_READ_PNA;
			break;
		case 5:
			command = PSL_COMMAND_TOUCH_I;
			break;
		case 6:
			command = PSL_COMMAND_TOUCH_S;
			break;
		case 7:
			command = PSL_COMMAND_TOUCH_M;
			break;
		case 8:
			command = PSL_COMMAND_WRITE_MI;
			break;
		case 9:
			command = PSL_COMMAND_WRITE_MS;
			break;
		case 10:
			command = PSL_COMMAND_WRITE_NA;
			break;
		case 11:
			command = PSL_COMMAND_WRITE_INJ;
			break;
		case 12:
			command = PSL_COMMAND_PUSH_I;
			break;
		case 13:
			command = PSL_COMMAND_PUSH_S;
			break;
		case 14:
			command = PSL_COMMAND_EVICT_I;
			break;
		default:
			command = PSL_COMMAND_FLUSH;
		}
		set_machine_config_command_code(machine, command);
		set_machine_config_command_size(machine, 0x1 << (rand() % 8));
		if (enable_machine(afu_h, machine, i, DEDICATED) < 0) {
			printf("FAILED: enable_machine\n");
			stop_afu(afu_h);
			exit(-1);
		}
	}

	return afu_h;
}

void stop_test(struct cxl_afu_h *afu_h, MachineConfig *machine)
{
	int i;
	uint8_t response;

	// Stop AFU machines
	set_machine_config_disable(machine);
	for (i = 0; i < 64; i++) {
		if(enable_machine(afu_h, machine, i, DEDICATED) < 0) {
			stop_afu(afu_h);
			exit(-1);
		}
	}

	// Wait for all AFU machines to complete last command
	for (i = 0; i < 64; i++) {
		if ((response = get_response(afu_h, machine, i, DEDICATED))!=0)
		{
			printf("FAILED: Unexpected response code 0x%x\n", response);
			stop_afu(afu_h);
			exit(-1);
		}
	}
}

struct afu_list {
	struct cxl_afu_h *afu;
	struct afu_list *_next;
};

int main(int argc, char *argv[])
{
	MachineConfig machine;
	struct cxl_afu_h *afu_h;
	uint64_t wed;
	char *area, *name;
	unsigned seed;
	int i, opt, option_index, response;

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
	while ((opt = getopt_long (argc, argv, "hs:d:",
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

	// Allocate aligned memory area of 64 cachelines
	printf("Allocating and polluting memory area\n");
	if (posix_memalign((void **)&area, CACHELINE_BYTES, 64*CACHELINE_BYTES) != 0) {
		printf("FAILED:posix_memalign\n");
		return 0;
	}

	// Pollute memory area with random values
	for (i = 0; i < 64*CACHELINE_BYTES; i++)
		area[i] = rand();

	// Initialize machine configuration
	init_machine(&machine);

	// Find AFU
	afu_h = cxl_afu_next(NULL);

	// Open AFU
	printf("Opening %s\n", cxl_afu_dev_name(afu_h));
	if (!afu_h) {
		fprintf(stderr, "\nNo AFU found!\n\n");
		exit(-1);
	}
	afu_h = cxl_afu_open_h(afu_h, CXL_VIEW_DEDICATED);
	if (!afu_h) {
		perror("cxl_afu_open_h");
		exit(-1);
	}

	// Set WED to random value
	wed = rand();
	wed <<= 32;
	wed |= rand();

	// Start AFU
	cxl_afu_attach(afu_h, wed);

	// Map AFU MMIO registers
	if ((cxl_mmio_map(afu_h, CXL_MMIO_BIG_ENDIAN)) < 0) {
		perror("cxl_mmio_map");
		cxl_afu_free(afu_h);
		exit(-1);
	}

	// Have each AFU Machine read a unique cacheline in memory area to
	// get initial values into AFU
	printf("Load each machine with initial data\n");
	for (i = 0; i < 64; i++) {
		if (config_and_enable_machine(afu_h, &machine, i, 0,
					      PSL_COMMAND_READ_CL_NA,
					      CACHELINE_BYTES, 0, 0,
					      (uint64_t)area+CACHELINE_BYTES*i,
					      CACHELINE_BYTES, 0, DEDICATED)
					      < 0)
		{
			printf("FAILED:config_and_enable_machine");
			stop_afu(afu_h);
			exit(-1);
		}
	}

	// Check for valid response
	for (i = 0; i < 64; i++) {
		if ((response = get_response(afu_h, &machine, i, DEDICATED))!=0)
		{
			printf("FAILED: Unexpected response code 0x%x\n",
			       response);
			stop_afu(afu_h);
			exit(-1);
		}
	}

	// Start AFU machines
	printf("Starting random cacheline accesses\n");
	start_test(afu_h, &machine, area);

	// Tell each AFU machine to stop generating commands
	printf("Stopping random cacheline accesses\n");
	stop_test(afu_h, &machine);

	// Wait for each AFU to complete
	printf("Stopping %s\n", cxl_afu_dev_name(afu_h));
	stop_afu(afu_h);

	// Report if test passed
	printf("PASSED\n");

	return 0;
}
