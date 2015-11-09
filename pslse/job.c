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

#include <assert.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

#include "job.h"
#include "../common/debug.h"

// Initialize job tracking structure
struct job *job_init(struct AFU_EVENT *afu_event,
		     volatile enum pslse_state *psl_state, char *afu_name,
		     FILE * dbg_fp, uint8_t dbg_id)
{
	struct job *job;

	// Initialize job struct
	job = (struct job *)calloc(1, sizeof(struct job));
	if (!job)
		return job;
	job->afu_event = afu_event;
	job->psl_state = psl_state;
	job->afu_name = afu_name;
	job->dbg_fp = dbg_fp;
	job->dbg_id = dbg_id;
	return job;
}

// Create new pe to send to AFU
struct job_event *add_pe(struct job *job, uint32_t code, uint64_t addr)
{
        struct job_event **tail;
	struct job_event *this;
	struct job_event *event;

	// Find the end of the list
	// tail = &(job->pe);
	// while (*tail != NULL)
	// 	tail = &((*tail)->_next);

	if (job->pe == NULL) {
	  debug_msg("%s,%d:add_pe, first pe, code=0x%02x addr=0x%16"PRIx64, job->afu_name, job->dbg_id, code, addr );
	  tail = &(job->pe);
	} else {
	  debug_msg("%s,%d:add_pe, subsequent pe, code=0x%02x addr=0x%16"PRIx64, job->afu_name, job->dbg_id, code, addr );
	  this = job->pe;
	  debug_msg("%s,%d:add_pe this=0x%16"PRIx64, job->afu_name, job->dbg_id, this );
	  while (this->_next != NULL) {
	    debug_msg("%s,%d:add_pe this=0x%16"PRIx64, job->afu_name, job->dbg_id, this );
	    debug_msg("%s,%d:add_pe _next=0x%16"PRIx64, job->afu_name, job->dbg_id, this->_next );
	    this = this->_next;
	  }
	  tail = &(this->_next);
	}
	debug_msg("%s,%d:add_pe (first) tail=0x%16"PRIx64, job->afu_name, job->dbg_id, tail );

	// Create new pe job event and add to end of list
	event = (struct job_event *)calloc(1, sizeof(struct job_event));
	if (!event)
		return event;
	event->code = code;
	event->addr = addr;
	event->state = PSLSE_IDLE;
	event->_next = NULL;
	*tail = event;

	// DEBUG
	debug_job_add(job->dbg_fp, job->dbg_id, event->code);

	return event;
}

void send_pe(struct job *job)
{
	struct job_event *event;

	// this needs to block the send of the "next" pe until 
	// the job is running
	// and the previous pe is running

	// Test for valid job
	if ((job == NULL) || (job->job == NULL))
		return;

	// Client disconnected - free com event linked list
	// fixme
	/* if (job->com->state == PSLSE_DONE) { */
	/* 	event = job->com; */
	/* 	job->com = event->_next; */
	/* 	free(event); */
	/* 	return; */
	/* } */

	// Test for running job
	// I think we need to make sure running is set upon receipt of the jrunning ack
	if ( *(job->psl_state) != PSLSE_RUNNING )
		return;

	// Test for valid pe
	// do this in a loop, checking each pe in the list
	event = job->pe;
	while (event != NULL) {
	   switch (event->state) {
	   case PSLSE_PENDING:
	      // is event pending?  leave - we have to wait for this one to finish
	      return;
	   case PSLSE_IDLE:
	      // is event idle? send it and return
	      // is psl_job_control the right routine to use?
	      if (psl_job_control(job->afu_event, event->code, event->addr) == PSL_SUCCESS) {
	         event->state = PSLSE_PENDING;
	         debug_msg("%s:LLCMD code=0x%02x ea=0x%016" PRIx64, job->afu_name,
		          event->code, event->addr);

	         // DEBUG
	         debug_job_send(job->dbg_fp, job->dbg_id, event->code);
	      }
	      return;
	   default:
	      // error?
	      return;
	      break;
           }  
	}
	return;
}

// Create new job to send to AFU
struct job_event *add_job(struct job *job, uint32_t code, uint64_t addr)
{
	struct job_event **tail;
	struct job_event *event;

	// For resets, dump previous job if not reset
	while ((code == PSL_JOB_RESET) && (job->job != NULL) &&
	       (job->job->code != PSL_JOB_RESET)) {
		event = job->job;
		job->job = event->_next;
		free(event);
	}

	// Find the end of the list
	tail = &(job->job);
	while (*tail != NULL)
		tail = &((*tail)->_next);

	// Create new job event and add to end of list
	event = (struct job_event *)calloc(1, sizeof(struct job_event));
	if (!event)
		return event;
	event->code = code;
	event->addr = addr;
	event->state = PSLSE_IDLE;
	*tail = event;

	// DEBUG
	debug_job_add(job->dbg_fp, job->dbg_id, event->code);

	return event;
}

void send_job(struct job *job)
{
	struct job_event *event;

	// Test for valid job
	if ((job == NULL) || (job->job == NULL))
		return;

	// Client disconnected - _free sets job->state, not job->job->state
	if (job->job->state == PSLSE_DONE) {
		event = job->job;
		job->job = event->_next;
		free(event);
		return;
	}
	// Test for valid job
	event = job->job;
	if ((event == NULL) || (event->state == PSLSE_PENDING))
		return;

	// Attempt to send job to AFU
	if (psl_job_control(job->afu_event, event->code, event->addr) ==
	    PSL_SUCCESS) {
		event->state = PSLSE_PENDING;
		debug_msg("%s:JOB code=0x%02x ea=0x%016" PRIx64, job->afu_name,
			  event->code, event->addr);
		// Change job state
		if (event->code == PSL_JOB_RESET)
			*(job->psl_state) = PSLSE_RESET;

		// DEBUG
		debug_job_send(job->dbg_fp, job->dbg_id, event->code);
	}
}

// See if AFU changed any of the aux2 signals and handle accordingly
int handle_aux2(struct job *job, uint32_t * parity, uint32_t * latency,
		uint64_t * error)
{
	struct job_event **_prev;
	struct job_event *event;
	uint32_t job_running;
	uint32_t job_done;
	uint32_t job_cack_llcmd;
	uint64_t job_error;
	uint32_t job_yield;
	uint32_t tb_request;
	uint32_t par_enable;
	uint32_t read_latency;
	uint8_t dbg_aux2;
	int reset, reset_complete;

	if (job == NULL)
		return 0;

	// See if AFU is driving AUX2 signal changes
	dbg_aux2 = reset = reset_complete = *error = 0;
	if (psl_get_aux2_change(job->afu_event, &job_running, &job_done,
				&job_cack_llcmd, &job_error, &job_yield,
				&tb_request, &par_enable, &read_latency) ==
	    PSL_SUCCESS) {
		// Handle job_done
		if (job_done) {
			debug_msg("%s:JOB done", job->afu_name);
			dbg_aux2 |= DBG_AUX2_DONE;
			*error = job_error;
			if (job->job != NULL) {
				event = job->job;
				// Is job_done for reset or start?
				if (event->code == PSL_JOB_RESET)
					reset_complete = 1;
				else
					reset = 1;
				job->job = event->_next;
				free(event);
				if (job->job != NULL)
					assert(job->job->_next != job->job);
			}
			if (*(job->psl_state) == PSLSE_RESET) {
				*(job->psl_state) = PSLSE_IDLE;
			}
		}
		// Handle job_running
		if (job_running) {
			debug_msg("%s:JOB running", job->afu_name);
			*(job->psl_state) = PSLSE_RUNNING;
			dbg_aux2 |= DBG_AUX2_RUNNING;
		}
		if (job_cack_llcmd) {
		        // remove the current pending pe from the list
		        // loop through the pe's for the current pending one;
		        // copy its _next to _prev's _next
		        // remove the current pe
		        _prev = &(job->pe);
			while (*_prev != NULL) {
			  if ((*_prev)->state == PSLSE_PENDING) {
			      event = *_prev;
			      _prev = &((*_prev)->_next);
			      free(event);
			   } else {
			      _prev = &((*_prev)->_next);
			   }
			}
		        debug_msg("%s:LLCMD running", job->afu_name);
			dbg_aux2 |= DBG_AUX2_LLCACK;
		}
		if (tb_request) {
			dbg_aux2 |= DBG_AUX2_TBREQ;
		}
		if (par_enable) {
			dbg_aux2 |= DBG_AUX2_PAREN;
		}
		dbg_aux2 |= read_latency & DBG_AUX2_LAT_MASK;
		if (job_done && job_running)
			error_msg("ah_jdone & ah_jrunning asserted together");
		if ((read_latency != 1) && (read_latency != 3))
			warn_msg("ah_brlat must be either 1 or 3");
		*parity = par_enable;
		*latency = read_latency;

		// DEBUG
		debug_job_aux2(job->dbg_fp, job->dbg_id, dbg_aux2);
	}

	if (reset)
		add_job(job, PSL_JOB_RESET, 0L);

	return reset_complete;
}
