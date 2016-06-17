/*
 * Copyright 2014,2015 International Business Machines
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

#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "parms.h"
#include "../common/utils.h"
#include "../common/debug.h"

#define DEFAULT_CREDITS 64

// Randomly decide based on percent chance
static inline int percent_chance(int chance)
{
	return ((rand() % 100) < chance);
}

// Randomly decide to allow response to AFU
int allow_resp(struct parms *parms)
{
	return percent_chance(parms->resp_percent);
}

// Randomly decide to allow PAGED response
int allow_paged(struct parms *parms)
{
	return percent_chance(parms->paged_percent);
}

// Randomly decide to allow command to be handled out of order
int allow_reorder(struct parms *parms)
{
	return percent_chance(parms->reorder_percent);
}

// Randomly decide to allow bogus buffer activity
int allow_buffer(struct parms *parms)
{
	return percent_chance(parms->buffer_percent);
}

// Decide a single random percentage value from a percentage range
static void percent_parm(char *value, int *parm)
{
	int min, max;
	char *comma;

	*parm = atoi(value);
	comma = strchr(value, ',');
	if (comma) {
		min = *parm;
		*comma = '\0';
		++comma;
		max = atoi(comma);
		if (max < min) {
			min = max;
			max = *parm;
		}
		*parm = min + (rand() % (1 + max - min));
	}
}

// Open and parse parms file
struct parms *parse_parms(char *filename, FILE * dbg_fp)
{
	struct parms *parms;
	char parm[MAX_LINE_CHARS];
	char *value;
	FILE *fp;
	int data;

	// Allocate memory for struct
	parms = (struct parms *)malloc(sizeof(struct parms));
	if (parms == NULL)
		return NULL;

	// Set default parameter values
	parms->timeout = 10;
	parms->credits = DEFAULT_CREDITS;
	parms->seed = (unsigned int)time(NULL);
	parms->resp_percent = 20;
	parms->paged_percent = 5;
	parms->reorder_percent = 20;
	parms->buffer_percent = 50;

	// Open file and parse contents
	fp = fopen(filename, "r");
	if (fp == NULL) {
		perror("fopen");
		free(parms);
		return NULL;
	}
	while (fgets(parm, MAX_LINE_CHARS, fp)) {
		// Strip newline char
		value = strchr(parm, '\n');
		if (value)
			*value = '\0';

		// Skip comment lines
		value = strchr(parm, '#');
		if (value)
			continue;

		// Skip blank lines
		value = strchr(parm, ' ');
		if (value)
			*value = '\0';
		value = strchr(parm, '\t');
		if (value)
			*value = '\0';
		if (!strlen(parm))
			continue;

		// Look for valid parms
		value = strchr(parm, ':');
		if (value) {
			*value = '\0';
			++value;
		} else {
			error_msg("Invalid format in %s: Expected ':', %s",
				  filename, parm);
			continue;
		}

		// Set valid parms
		if (!(strcmp(parm, "SEED"))) {
			parms->seed = atoi(value);
			debug_parm(dbg_fp, DBG_PARM_SEED, parms->seed);
		} else if (!(strcmp(parm, "TIMEOUT"))) {
			parms->timeout = atoi(value);
			debug_parm(dbg_fp, DBG_PARM_TIMEOUT, parms->timeout);
		} else if (!(strcmp(parm, "CREDITS"))) {
			data = atoi(value);
			if ((data > DEFAULT_CREDITS) || (data <= 0))
				warn_msg("CREDITS must be 1-%d",
					 DEFAULT_CREDITS);
			else
				parms->credits = data;
			debug_parm(dbg_fp, DBG_PARM_CREDITS, parms->credits);
		} else if (!(strcmp(parm, "RESPONSE_PERCENT"))) {
			percent_parm(value, &data);
			if ((data > 100) || (data <= 0))
				warn_msg("RESPONSE_PERCENT must be 1-100");
			else
				parms->resp_percent = data;
			debug_parm(dbg_fp, DBG_PARM_RESP_PERCENT,
				   parms->resp_percent);
		} else if (!(strcmp(parm, "PAGED_PERCENT"))) {
			percent_parm(value, &data);
			if ((data >= 100) || (data < 0))
				warn_msg("PAGED_PERCENT must be 0-99");
			else
				parms->paged_percent = data;
			debug_parm(dbg_fp, DBG_PARM_PAGED_PERCENT,
				   parms->paged_percent);
		} else if (!(strcmp(parm, "REORDER_PERCENT"))) {
			percent_parm(value, &data);
			if ((data >= 100) || (data < 0))
				warn_msg("REORDER_PERCENT must be 0-99");
			else
				parms->reorder_percent = data;
			debug_parm(dbg_fp, DBG_PARM_REORDER_PERCENT,
				   parms->reorder_percent);
		} else if (!(strcmp(parm, "BUFFER_PERCENT"))) {
			percent_parm(value, &data);
			if ((data >= 100) || (data < 0))
				warn_msg("BUFFER_PERCENT must be 0-99");
			else
				parms->buffer_percent = data;
			debug_parm(dbg_fp, DBG_PARM_BUFFER_PERCENT,
				   parms->buffer_percent);
		} else if (!(strcmp(parm, "CAIA_VERSION"))) {
			parms->caia_version = atoi(value);
			debug_parm(dbg_fp, DBG_CAIA_VERSION, parms->caia_version);
		} else if (!(strcmp(parm, "PSL_REV_LEVEL"))) {
			parms->psl_rev_level = atoi(value);
			debug_parm(dbg_fp, DBG_PSL_REV_LVL, parms->psl_rev_level);
		} else if (!(strcmp(parm, "IMAGE_LOADED"))) {
			parms->image_loaded = atoi(value);
			debug_parm(dbg_fp, DBG_IMAGE_LOADED, parms->image_loaded);
		} else if (!(strcmp(parm, "BASE_IMAGE_REV_LEVEL"))) {
			parms->base_image = atoi(value);
			debug_parm(dbg_fp, DBG_BASE_IMAGE, parms->base_image);
		} else {
			warn_msg("Ignoring invalid parm in %s: %s\n",
				 filename, parm);
			continue;
		}
	}

	// Close file and set seed
	fclose(fp);
	srand(parms->seed);

	// Print out parm settings
	info_msg("PSLSE parm values:");
	printf("\tSeed     = %d\n", parms->seed);
	if (parms->credits != DEFAULT_CREDITS)
		printf("\tCredits  = %d\n", parms->credits);
	if (parms->timeout)
		printf("\tTimeout  = %d seconds\n", parms->timeout);
	else
		printf("\tTimeout  = DISABLED\n");
	printf("\tResponse = %d%%\n", parms->resp_percent);
	printf("\tPaged    = %d%%\n", parms->paged_percent);
	printf("\tReorder  = %d%%\n", parms->reorder_percent);
	printf("\tBuffer   = %d%%\n", parms->buffer_percent);
//When we start reading these values in from pslse.parms, uncomment
//	printf("\tCAIA_Ver     = %4d\n", parms->caia_version);
//	printf("\tPSL_REV      = %d\n", parms->psl_rev_level);
//	printf("\tImage_Loaded = %d\n", parms->image_loaded);
//	printf("\tBase_Image   = %d\n", parms->base_image);

	// Adjust timeout to milliseconds
	parms->timeout *= 1000;

	return parms;
}
