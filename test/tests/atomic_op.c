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

union OP {
    unsigned char byte[8];
    uint64_t	lword0;
} op_data;

struct OP_S {
    char op_name[20];
    int  opcode;
};

enum FETCH_OP {
    FETCHADD=0x1F20, FETCHXOR, FETCHOR, FETCHAND, FETCHMAXUNSIGNED, FETCHMAXSIGNED,
    FETCHMINUNSIGNED, FETCHMINSIGNED, CSUNCONDITION, CSNOTEQUAL=0x1F30, CSEQUAL=0x1F31,
    FETCHINCBOUNDED=0x1F38, FETCHINCEQUAL=0x1F39, FETCHDECBOUNDED=0x1F3C 
} fetch_op;
 enum STORE_OP {
    STOREADD=0x1F40, STOREXOR, STOREOR, STOREAND, STOREMAXUNSIGNED, STOREMAXSIGNED,
    STOREMINUNSIGNED, STOREMINSIGNED, STORETWIN=0x1F58
} store_op;

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
	uint64_t op_value = 0x0706050403020100;
	uint64_t wed;
	unsigned seed;
	int i, j, opt, option_index;	// quadrant, byte;
	int response;
	int context, machine_number;
	bool result;
	int command;
	char op_name[32];
	struct OP_S fetch[] = { {"FETCHADD",0x1F20}, {"FETCHXOR", 0x1F21}, {"FETCHOR", 0x1F22},
                        {"FETCHAND",0x1F23}, {"FETCHMAXUNSIGNED", 0x1F24}, {"FETCHMAXSIGNED",0x1F25},
                        {"FETCHMINUNSIGNED",0x1F26}, {"FETCHMINSIGNED",0x1F27}, {"CSUNCONDITION",0x1F28},
                        {"CSNOTEQUAL",0x1F30}, {"CSEQUAL",0x1F31}, {"FETCHINCBOUNDED",0x1F38},
                        {"FETCHINCEQUAL",0x1F39}, {"FETCHDECBOUNDED",0x1F3C} } ;
	struct OP_S store[] = { {"STOREADD",0x1F40}, {"STOREXOR",0x1F41}, {"STOREOR",0x1F42}, 
                        {"STOREAND",0x1F43}, {"STOREMAXUNSIGNED",0x1F44}, {"STOREMAXSIGNED",0x1F45},
                        {"STOREMINUNSIGNED",0x1F46}, {"STOREMINSIGNED",0x1F47}, {"STORETWIN",0x1F58} };
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
	printf("APP: Attaching AFU master\n");
	if (cxl_afu_attach(afu_m, wed) < 0) {
            perror("FAILED:cxl_afu_attach for master");
		goto done;
        }

	printf("APP: wed = 0x%"PRIx64"\n", wed);

	// Map AFU MMIO registers
	printf("APP: Mapping AFU master registers...\n");
	if ((cxl_mmio_map(afu_m, CXL_MMIO_BIG_ENDIAN)) < 0) {
		perror("cxl_mmio_map for master");
		goto done;

	}

	context = cxl_afu_get_process_element(afu_m);

	printf("APP: Master context = %d\n", context);
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
	}
	
	printf("APP: XLAT_RD Fetch and ADD cacheline0 address = 0x%x\n", cacheline0);
	//printf("APP: cacheline0 data = 0x");
	for(i=0; i<8; i++) {
	    op_data.byte[i] = cacheline0[i];
	    //printf("%02x", op_data.byte[i]);
	}
	printf("\n");
	// Initialize machine configuration
	printf("APP: initialize machine\n");
	init_machine(&machine);

	// Atomic Fetch operations
	for(j=0; j<14; j++)
	{
	    sleep(2);
	    command = fetch[j].opcode;
	    printf("===============================================\n");
	    printf("APP: Testing %s\n", fetch[j].op_name);
	    for(i=0; i<8; i++) {
		op_data.byte[i] = cacheline0[i];
	    }
	    printf("APP: cacheline0 = 0x%016"PRIx64"\n", op_data.lword0);
	    if((response = config_enable_and_run_machine(afu_m, &machine, 0, context,
	        command, CACHELINE_BYTES, 0, 0, (uint64_t)cacheline0,
	        CACHELINE_BYTES, DIRECTED_M)) < 0)
	    {
	        printf("APP: FAILED: config_enable_and_run_machine for master Fetch \
			commands response = %d\n", response);
	        goto done;
	    }
	    // Check for valid response
	    if (response != PSL_RESPONSE_DONE)
	    {
		printf("APP: FAILED: Unexpected response code 0x%x\n", response);
		goto done;
	    }

	    switch (command) {
		case FETCHADD:
		    op_data.lword0 = op_data.lword0 + op_value;
		    strcpy(op_name, "Fetch and ADD");
		    printf("APP: %s = 0x%x\n", op_name, command);
		    break;
		case FETCHXOR:
		    op_data.lword0 = op_data.lword0 ^ op_value;
		    strcpy(op_name, "Fetch and XOR");
		    printf("APP: %s = 0x%x\n", op_name, command);
		    break;
		case FETCHOR:
		    op_data.lword0 = op_data.lword0 | op_value;
		    strcpy(op_name, "Fetch and OR");
		    printf("APP: %s = 0x%x\n", op_name, command);
		    break;
		case FETCHAND:
		    op_data.lword0 = op_data.lword0 & op_value;
		    strcpy(op_name, "Fetch and AND");
		    printf("APP: %s = 0x%x\n", op_name, command);
		    break;
		case FETCHMAXUNSIGNED:
		    strcpy(op_name, "Fetch and Max Unsigned");
		    printf("APP: %s = 0x%x\n", op_name, command);
		    break;
		case FETCHMAXSIGNED:
		    strcpy(op_name, "Fetch and Max Signed");
		    printf("APP: %s = 0x%x\n", op_name, command);
		    break;
		case FETCHMINUNSIGNED:
		    strcpy(op_name, "Fetch and Min Unsigned");
		    printf("APP: %s = 0x%x\n", op_name, command);
		    break;
		case FETCHMINSIGNED:
		    strcpy(op_name, "Fetch and Min Signed");
		    printf("APP: %s = 0x%x\n", op_name, command);
		    break;
		case CSNOTEQUAL:
		    strcpy(op_name, "Compare and Swap Not Equal");
		    printf("APP: %s = 0x%x\n", op_name, command);
		    if(memcmp(&op_value, &op_data.lword0, 8) != 0) {
			result = true;
		    }
		    else {
			result = false;
			printf("cacheline0 = 0x%016"PRIx64" op_value = 0x%016"PRIx64"\n",
				cacheline0, op_value);
		    }
		    break;
		case CSEQUAL:
		    strcpy(op_name, "Compare and Swap Equal");
		    printf("APP: %s = 0x%x\n", op_name, command);
		    if(memcmp(&op_value, &op_data.lword0, 8) == 0) {
			result = true;
		    }
		    else {
			result = false;
			printf("cacheline0 = 0x%016"PRIx64" op_value = 0x%016"PRIx64"\n",
				op_data.lword0, op_value);
		    }
		    break;
		case CSUNCONDITION:
		    strcpy(op_name, "Compare and Swap Unconditional");
		    printf("APP: %s = 0x%x\n", op_name, command);
		    break;
		case FETCHINCBOUNDED:
		    strcpy(op_name, "Fetch and Increment Bounded");
		    printf("APP: %s = 0x%x\n", op_name, command);
		    break;
		case FETCHINCEQUAL:
		    strcpy(op_name, "Fetch and Increment Equal");
		    printf("APP: %s = 0x%x\n", op_name, command);
		    break;
		case FETCHDECBOUNDED:
		    strcpy(op_name, "Fetch and Decrement Bounded");
		    printf("APP: %s = 0x%x\n", op_name, command);
		    break;
		default:
		    printf("No Fetch command founded\n");
		    break;
		}
		printf("APP: Comparing cacheline data for Fetch operation\n");
		printf("APP: Expected result = 0x%016"PRIx64"\n", op_data.lword0);
		printf("APP: op_value = 0x%016"PRIx64"\n", op_value);
		result = true;
		printf("cacheline \t op1\n");
		if ((command != CSNOTEQUAL) || (command != CSEQUAL) || (command != CSUNCONDITION))
		{
		    for(i=0; i<8; i++) {
	    	        printf("0x%02x\t\t0x%02x\n", (unsigned char)cacheline0[i], op_data.byte[i]);
	    	        if((unsigned char)cacheline0[i] != op_data.byte[i]) {
		 	    result = false;
			    printf("failed\n");
	       	        }
		    }
		}
		    
		if (result == false) {
		    printf("APP: FAILED compare %s command\n", op_name);
		}
		else {
		    printf("APP: completed %s\n", op_name);
		}
	}	// end for loop

	// Pollute first cacheline with random values
	for (i = 0; i < CACHELINE_BYTES; i++)
	{
		cacheline1[i] = rand();
	}

	// Atomic Store operations
	for(j=0; j<9; j++)
	{
	    sleep(2);
	    command = store[j].opcode;
	    printf("===============================================\n");
	    printf("APP: Testing %s\n", store[j].op_name);
	    for(i=0; i<8; i++) {
		op_data.byte[i] = cacheline1[i];
	    }
	    printf("APP: cacheline1 address = 0x%016"PRIx64"  data = 0x%016"PRIx64"\n", &op_data.lword0, op_data.lword0);
	    if((response = config_enable_and_run_machine(afu_m, &machine, 0, context,
	        command, CACHELINE_BYTES, 0, 0, (uint64_t)cacheline1,
	        CACHELINE_BYTES, DIRECTED_M)) < 0)
	    {
	        printf("APP: FAILED: config_enable_and_run_machine for master Fetch \
			commands response = %d\n", response);
	        goto done;
	    }
	    // Check for valid response
	    if (response != PSL_RESPONSE_DONE)
	    {
		printf("APP: FAILED: Unexpected response code 0x%x\n", response);
		goto done;
	    }

	    switch (command) {
		case STOREADD:
		    op_data.lword0 = op_data.lword0 + op_value;
		    strcpy(op_name, "Store and ADD");
		    break;
		case STOREXOR:
		    op_data.lword0 = op_data.lword0 ^ op_value;
		    strcpy(op_name, "Store and XOR");
		    break;
		case STOREOR:
		    op_data.lword0 = op_data.lword0 | op_value;
		    strcpy(op_name, "Store and OR");
		    break;
		case STOREAND:
		    op_data.lword0 = op_data.lword0 & op_value;
		    strcpy(op_name, "Store and AND");
		    break;
		case STOREMAXUNSIGNED:
		    strcpy(op_name, "Store and Max Unsigned");
		    break;
		case STOREMAXSIGNED:
		    strcpy(op_name, "Store and Max Signed");
		    break;
		case STOREMINUNSIGNED:
		    strcpy(op_name, "Store and Min Unsigned");
		    break;
		case STOREMINSIGNED:
		    strcpy(op_name, "Store and Min Signed");
		    break;
		case STORETWIN:
		    strcpy(op_name, "Store Twin");
		    break;
		default:
		    printf("No Store command founded\n");
		    break;
		}
		printf("APP: %s = 0x%x command\n", op_name, command);
		printf("APP: Comparing cacheline data for Store operation\n");
		printf("APP: Expected result = 0x%"PRIx64"\n", op_data.lword0);
		printf("APP: op_value = 0x%016"PRIx64"\n", op_value);
		result = true;
		printf("cacheline \t op1\n");
		for(i=0; i<8; i++) {
	    	    printf("0x%02x\t\t0x%02x\n", (unsigned char)cacheline1[i], op_data.byte[i]);
	    	    if((unsigned char)cacheline1[i] != op_data.byte[i]) {
		 	result = false;
			printf("failed\n");
	       	    }
		}
		if (result == false) {
		    printf("APP: FAILED compare %s command\n", op_name);
		}
		else {
		    printf("APP: completed %s\n", op_name);
		}
	}	// store end for loop


        
done:
        // unmap and free slave afu 
        //if (afu_s) {
        //    cxl_mmio_unmap(afu_s);
        //    cxl_afu_free(afu_s);
        //}
        // unmap and free master afu
	if (afu_m) {
		// Unmap AFU MMIO registers
		cxl_mmio_unmap(afu_m);

		// Free AFU
		cxl_afu_free(afu_m);
	}
       

	return 0;
}
