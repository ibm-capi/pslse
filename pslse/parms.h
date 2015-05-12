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

#ifndef _PARMS_H_
#define _PARMS_H_

#include <stdio.h>

struct parms {
	unsigned int timeout;
	unsigned int resp_percent;
	unsigned int paged_percent;
	unsigned int reorder_percent;
	unsigned int buffer_percent;
};

int allow_resp(struct parms* parms);

int allow_paged(struct parms* parms);

int allow_reorder(struct parms* parms);

int allow_buffer(struct parms* parms);

struct parms *parse_parms(char *filename, FILE *dbg_fp);

#endif /* _PARMS_H_ */
