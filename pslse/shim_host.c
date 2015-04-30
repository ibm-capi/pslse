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

/*
 * Description: shim_host.c
 *
 *  This file contains parse_host_data() which reads the file with the
 *  hostname and ports of each AFU simulator and calls psl_init for each.
 */

#include <malloc.h>
#include <stdio.h>
#include <stdlib.h>

#include "shim_host.h"
#include "../common/utils.h"

// Parse file to find hostname and ports for AFU simulator(s)
int parse_host_data(struct psl **head, struct parms *parms, char *filename) {
	FILE *fp;
	struct psl *psl;
	char *hostdata, *comment, *afu_id, *host, *port_str;
	int port;

	*head = NULL;
	fp = fopen(filename, "r");
	if (!fp) {
		hostdata = (char *) malloc(strlen(filename)+strlen("fopen:")+1);
		strcpy(hostdata, "fopen:");
		strcat(hostdata, filename);
		perror(hostdata);
		free(hostdata);
		return -1;
	}
	host = NULL;
	port_str = NULL;
	hostdata = (char *) malloc(MAX_LINE_CHARS);
	while (fgets(hostdata, MAX_LINE_CHARS-1, fp)) {
		// Parse host & port from file
		afu_id = hostdata;
		comment = strchr(hostdata, '#');
		if (comment)
			continue;
		host = strchr(hostdata, ',');
		if (host) {
			*host = '\0';
			++host;
		} else {
			error_msg("Invalid format in %s: Expected ',' :%s\n",
				  filename, hostdata);
			continue;
		}
		port_str = strchr(host, ':');
		if (port_str) {
			*port_str = '\0';
			++port_str;
		} else {
			error_msg("Invalid format in %s: Expected ':' :%s\n",
				  filename, host);
			continue;
		}
		if (!host) {
			error_msg("Invalid format in %s, hostname not found\n");
			continue;
		}
		if (!port_str) {
			error_msg("Invalid format in %s, Port not found\n");
			continue;
		}
		port = atoi(port_str);

		// Initialize PSL
		if (psl_init(head, parms, afu_id, host, port) < 0)
			continue;

		// Update all psl entries to point to new list head
		psl = *head;
		while (psl) {
			psl->head = head;
			psl = psl->_next;
		}
	}
	free(hostdata);
	fclose(fp);

	return 0;
}
