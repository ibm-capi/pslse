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
 * Description: job.c
 *
 *  This file contains the code for send jobs send to the AFU and tracking.
 *  The aux2 group of signals from the AFU.  Only one job is valid at one time.
 *  Currently only RESET and START are supported.  More support will be needed
 *  here for implementing "directed mode" AFU support.
 */

#include <inttypes.h>
#include <malloc.h>
#include <string.h>

#include "job.h"

// Initialize job tracking structure
struct job *job_init(struct AFU_EVENT *afu_event, pthread_mutex_t *psl_lock,
		     volatile enum pslse_state *psl_state)
{
	struct job *job;

	job = (struct job*) malloc(sizeof(struct job));
	if (!job)
		return job;
	memset(job, 0, sizeof(struct job));
	job->afu_event = afu_event;
	job->psl_lock = psl_lock;
	pthread_mutex_init(&(job->lock), NULL);
	job->psl_state = psl_state;
	return job;
}

// Create new job to send to AFU
struct job_event *add_job(struct job *job, uint32_t code, uint64_t addr)
{
	struct job_event *event;

	event = (struct job_event *) malloc(sizeof(struct job_event));
	if (!event)
		return event;
	event->code = code;
	event->addr = addr;
	event->state = PSLSE_IDLE;
	job->job = event;
	DPRINTF("Putting JOB event in queue\n");

	return event;
}

// Send pending job to AFU
void send_job(struct job *job)
{
	struct job_event *event;

	// Test for valid job
	if (job == NULL)
		return;

	pthread_mutex_lock(job->psl_lock);
	// Job not assigned yet
	if (job->job == NULL)
		goto send_done;
	// Client disconnected
	if (job->job->state == PSLSE_DONE) {
		free(job->job);
		job->job = NULL;
		goto send_done;
	}
	event = job->job;
	if (event == NULL)
		goto send_done;
	if (event->state == PSLSE_PENDING)
		goto send_done;

	// Attempt to send job to AFU
	if(psl_job_control(job->afu_event, event->code, event->addr) ==
	   PSL_SUCCESS) {
		DPRINTF("JOB event to AFU\n");
		// Change state for reset only
		event->state = PSLSE_PENDING;
		if (event->code == PSL_JOB_RESET)
			*(job->psl_state) = PSLSE_RESET;
	}
send_done:
	pthread_mutex_unlock(job->psl_lock);
}

// See if AFU changed any of the aux2 signals and handle accordingly
void handle_aux2(struct job *job, uint32_t *parity, uint32_t *latency)
{
	uint32_t job_running;
	uint32_t job_done;
	uint32_t job_cack_llcmd;
	uint64_t job_error;
	uint32_t job_yield;
	uint32_t tb_request;
	uint32_t par_enable;
	uint32_t read_latency;

	if (job == NULL)
		return;

	pthread_mutex_lock(job->psl_lock);

	if (psl_get_aux2_change(job->afu_event, &job_running, &job_done,
				&job_cack_llcmd, &job_error, &job_yield,
				&tb_request, &par_enable, &read_latency) ==
	    PSL_SUCCESS) {
		DPRINTF("AUX2 event from AFU\n");
		DPRINTF(" ah_jrunning=%d", job_running);
		DPRINTF(" ah_jdone=%d", job_done);
		DPRINTF(" ah_jerror=0x%016"PRIx64"\n", job_error);
		DPRINTF(" ah_jcack=%d", job_cack_llcmd);
		DPRINTF(" ah_tbreq=%d", tb_request);
		DPRINTF(" ah_paren=%d", par_enable);
		DPRINTF(" ah_brlat=%d\n", read_latency);
		if (job_done) {
			if (job->job != NULL) {
				free(job->job);
				job->job = NULL;
			}
			else {
				error_msg("Unexpected jdone=1 from AFU");
			}
			if (*(job->psl_state) != PSLSE_RESET) {
				DPRINTF("Sending reset to AFU\n");
				add_job(job, PSL_JOB_RESET, 0L);
				*(job->psl_state) = PSLSE_RESET;
			}
			else {
				*(job->psl_state) = PSLSE_IDLE;
			}
		}
		if (job_running)
			*(job->psl_state) = PSLSE_RUNNING;
		if (job_done && job_running)
			error_msg("ah_jdone & ah_jrunning asserted together");
		if ((read_latency != 1) && (read_latency != 3))
			warn_msg("ah_brlat must be either 1 or 3");
		*parity = par_enable;
		*latency = read_latency;
	}
	pthread_mutex_unlock(job->psl_lock);
}
