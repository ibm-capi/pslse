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

#include <malloc.h>
#include <stdlib.h>
#include <string.h>

#include "parms.h"
#include "../common/utils.h"

static inline int percent_chance(unsigned int chance)
{
	return ((rand() % 100) < chance);
}

int allow_resp(struct parms* parms)
{
	return percent_chance(parms->resp_percent);
}

int allow_paged(struct parms* parms)
{
	return percent_chance(parms->paged_percent);
}

int allow_reorder(struct parms* parms)
{
	return percent_chance(parms->reorder_percent);
}

int allow_buffer(struct parms* parms)
{
	return percent_chance(parms->buffer_percent);
}

static void percent_parm(char *value, unsigned int *parm)
{
	unsigned min, max;
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

struct parms* parse_parms(char *filename)
{
	struct parms* parms;
	char parm[MAX_LINE_CHARS];
	char *value;
	FILE *fp;
	unsigned int data;

	// Allocate memory for struct
	parms = (struct parms*) malloc(sizeof(struct parms));
	if (parms == NULL)
		return NULL;

	// Set default parameter values
	parms->timeout = 10;
	parms->resp_percent = 20;
	parms->paged_percent = 5;
	parms->reorder_percent = 20;
	parms->buffer_percent = 50;

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
		if (!(strcmp(parm, "TIMEOUT"))) {
			parms->timeout = atoi(value);
		} else if (!(strcmp(parm, "RESPONSE_PERCENT"))) {
			percent_parm(value, &data);
			if ((data > 100) || (data <= 0))
				warn_msg("RESPONSE_PERCENT must be 1-100");
			else
				parms->resp_percent = data;
		} else if (!(strcmp(parm, "PAGED_PERCENT"))) {
			percent_parm(value, &data);
			if ((data >= 100) || (data < 0))
				warn_msg("PAGED_PERCENT must be 0-99");
			else
				parms->paged_percent = data;
		} else if (!(strcmp(parm, "REORDER_PERCENT"))) {
			percent_parm(value, &data);
			if ((data >= 100) || (data < 0))
				warn_msg("REORDER_PERCENT must be 0-99");
			else
				parms->reorder_percent = data;
		} else if (!(strcmp(parm, "BUFFER_PERCENT"))) {
			percent_parm(value, &data);
			if ((data >= 100) || (data < 0))
				warn_msg("BUFFER_PERCENT must be 0-99");
			else
				parms->buffer_percent = data;
		} else {
			error_msg("Ignoring invalid parm in %s: %s\n",
				  filename, parm);
		}
	}
	fclose(fp);

	info_msg("PSLSE parm values:");
	if (parms->timeout)
		printf("\tTimeout  = %d seconds\n", parms->timeout);
	else
		printf("\tTimeout  = DISABLED\n");
	printf("\tResponse = %d%%\n", parms->resp_percent);
	printf("\tPaged    = %d%%\n", parms->paged_percent);
	printf("\tReorder  = %d%%\n", parms->reorder_percent);
	printf("\tBuffer   = %d%%\n", parms->buffer_percent);

	return parms;
}
