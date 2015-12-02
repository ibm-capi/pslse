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

#ifndef _JOB_H_
#define _JOB_H_

#include <stdint.h>
#include <stdio.h>

#include "../common/psl_interface.h"
#include "../common/utils.h"

struct job_event {
	uint32_t code;
	uint64_t addr;
	enum pslse_state state;
	struct job_event *_next;
};

struct job {
	struct AFU_EVENT *afu_event;
	struct job_event *job;
	struct job_event *pe;
	volatile enum pslse_state *psl_state;
	uint32_t read_latency;
	char *afu_name;
	FILE *dbg_fp;
	uint8_t dbg_id;
};

struct job *job_init(struct AFU_EVENT *afu_event,
		     volatile enum pslse_state *psl_state, char *afu_name,
		     FILE * dbg_fp, uint8_t dbg_id);

struct job_event *add_pe(struct job *job, uint32_t code, uint64_t addr);

void send_pe(struct job *job);

struct job_event *add_job(struct job *job, uint32_t code, uint64_t addr);

void send_job(struct job *job);

int handle_aux2(struct job *job, uint32_t * parity, uint32_t * latency,
		uint64_t * error);

#endif				/* _JOB_H_ */
