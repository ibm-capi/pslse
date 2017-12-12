/*
 * Copyright 2014,2016 International Business Machines
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

#ifndef _PARMS_H_
#define _PARMS_H_

#include <stdio.h>
#include "../common/psl_interface.h"

struct parms {
	unsigned int timeout;
	unsigned int credits;
	unsigned int seed;
#if defined PSL9 || defined PSL9lite
	unsigned int pagesize;
#endif
	unsigned int resp_percent;
	unsigned int paged_percent;
	unsigned int reorder_percent;
	unsigned int buffer_percent;
	unsigned int caia_version;
	unsigned int psl_rev_level;
	unsigned int image_loaded;
	unsigned int base_image;
};

// Randomly decide to allow response to AFU
int allow_resp(struct parms *parms);

// Randomly decide to allow PAGED response
int allow_paged(struct parms *parms);

// Randomly decide to allow command to be handled out of order
int allow_reorder(struct parms *parms);

// Randomly decide to allow bogus buffer activity
int allow_buffer(struct parms *parms);

// Open and parse parms file
struct parms *parse_parms(char *filename, FILE * dbg_fp);

#endif				/* _PARMS_H_ */
