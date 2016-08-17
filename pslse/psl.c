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
 * Description: psl.c
 *
 *  This file contains the foundation for the PSL code for a single AFU.
 *  psl_init() attempts to connect to an AFU simulator and initializes a
 *  psl struct if successful.  Finally it starts a _psl_loop thread for
 *  that AFU that will monitor any incoming socket data from either the
 *  simulator (AFU) or any clients (applications) that attach to this
 *  AFU.  The code in here is just the foundation for the psl.  The code
 *  for handling jobs, commands and mmios are each in there own separate files.
 */

#include <arpa/inet.h>
#include <assert.h>
#include <inttypes.h>
#include <poll.h>
#include <stdlib.h>
#include <sys/types.h>

#include "mmio.h"
#include "psl.h"
#include "../common/debug.h"
#include "../common/psl_interface.h"

// are there any pending commands with this context?
int _is_cmd_pending(struct psl *psl, int32_t context)
{
  struct cmd_event *cmd_event;

  if ( psl->cmd == NULL ) {
    // no cmd struct
    return 0;
  }

  cmd_event = psl->cmd->list;
  while ( cmd_event != NULL ) {
    if ( cmd_event->context == context ) {
      // found a matching element
      return 1;
    }
    cmd_event = cmd_event->_next;
  }

  // no matching elements found
  return 0;

}

// Attach to AFU
static void _attach(struct psl *psl, struct client *client)
{
	uint64_t wed;
	uint8_t ack;
	uint8_t buffer[MAX_LINE_CHARS];
	size_t size;

	// FIXME: This only works for dedicate mode
	// might work for afu-directed now - lgt

	// Get wed value from application
	// always do the get
        // pass the wed only for dedicated
	ack = PSLSE_DETACH;
	size = sizeof(uint64_t);
	if (get_bytes_silent(client->fd, size, buffer, psl->timeout,
			     &(client->abort)) < 0) {
	  warn_msg("Failed to get WED value from client");
	  client_drop(client, PSL_IDLE_CYCLES, CLIENT_NONE);
	  goto attach_done;
	}

	// but need to save wed if master|slave for future consumption
	// interestingly, I can always save it
	// add to client type.
	memcpy((char *)&wed, (char *)buffer, sizeof(uint64_t));
	client->wed = ntohll(wed);

	// Send start to AFU
	// only add PSL_JOB_START for dedicated and master clients.
	// send an empty wed in the case of master
	// lgt - new idea:
	// track number of clients in psl
	// if number of clients = 0, then add the start job
	// add llcmd add to client  (loop through clients in send_com)
	// increment number of clients (decrement where we handle the completion of the detach)
	switch (client->type) {
	case 'd':
	  if (psl->attached_clients == 0) {
	    if (add_job(psl->job, PSL_JOB_START, client->wed) != NULL) {
	      // if dedicated, we can ack PSLSE_ATTACH
	      // if master, we might want to wait until after the llcmd add is complete
	      // can I wait here for the START to finish?
	      psl->idle_cycles = PSL_IDLE_CYCLES;
	      ack = PSLSE_ATTACH;
	    }
	  }
	  break;
	case 'm':
	case 's':
	  if (psl->attached_clients < psl->max_clients) {
	    if (psl->attached_clients == 0) {
	      if (add_job(psl->job, PSL_JOB_START, 0L) != NULL) {
		// if master, we might want to wait until after the llcmd add is complete
		// can I wait here for the START to finish?
	      }
	    }
	    psl->idle_cycles = PSL_IDLE_CYCLES;
	    ack = PSLSE_ATTACH;
	  }
	  // running will be set by send/handle_aux2 routines
	  break;
	default:
	  // error?
	  break;
	}

	psl->attached_clients++;
	info_msg( "Attached client context %d: current attached clients = %d: client type = %c\n", client->context, psl->attached_clients, client->type );
	
	// for master and slave send llcmd add
        // master "wed" is 0x0005000000000000 can actually use client->context here as well since context = 0
	// slave "wed" is 0x000500000000hhhh where hhhh is the "handle" from client->context
	// now - about those llcmds :-)
	// put these in a separate list associated with the job?  psl->pe maybe...  or another call to add_job?
	// new routine to job.c?  add_cmd?
	// should a slave know their master?
	if (client->type == 'm' || client->type == 's') {
	        wed = PSL_LLCMD_ADD;
		wed = wed | (uint64_t)client->context;
		// add_pe adds to the client
	        if (add_pe(psl->job, PSL_JOB_LLCMD, wed) != NULL) {
		}
	}

 attach_done:
	if (put_bytes(client->fd, 1, &ack, psl->dbg_fp, psl->dbg_id,
		      client->context) < 0) {
		client_drop(client, PSL_IDLE_CYCLES, CLIENT_NONE);
	}
}

// Client is detaching from the AFU
static void _detach(struct psl *psl, struct client *client)
{
	uint64_t wed;

	debug_msg("DETACH from client context 0x%02x", client->context);
	// if dedicated mode just drop the client
	// if afu-directed mode
	//   add llcmd terminate to psl->job->pe
	//   add llcmd remove to psl->job->pe
	// comment - check to see if send pe is called if the client state is CLIENT_NONE
	// allow the socket to close and the client struct to be freed.
	if (client->type == 'm' || client->type == 's') {
	        wed = PSL_LLCMD_TERMINATE;
		wed = wed | (uint64_t)client->context;
	        if (add_pe(psl->job, PSL_JOB_LLCMD, wed) == NULL) {
		  // error
		  error_msg( "%s:_detach failed to add llcmd terminate for context=%d"PRIx64, psl->name, client->context );
		}
	        wed = PSL_LLCMD_REMOVE;
		wed = wed | (uint64_t)client->context;
	        if (add_pe(psl->job, PSL_JOB_LLCMD, wed) == NULL) {
		  // error
		  error_msg( "%s:_detach failed to add llcmd remove for context=%d"PRIx64, psl->name, client->context );
		}
	} else {
	  if (client->type == 'd' ) {
	    client_drop(client, PSL_IDLE_CYCLES, CLIENT_NONE);
	  }
	}

	// we will let _psl_loop call send_pe to issue the llcmds
	// when the jcack's come back, we will 
	//   send the detach response to the client and 
	//   free the client structure

	
}

// Client release from AFU
static void _free(struct psl *psl, struct client *client)
{
	struct cmd_event *mem_access;

	// DEBUG
	debug_context_remove(psl->dbg_fp, psl->dbg_id, client->context);

	info_msg("%s client disconnect from %s context %d", client->ip,
		 psl->name, client->context);
	close_socket(&(client->fd));
	if (client->ip)
		free(client->ip);
	client->ip = NULL;
	mem_access = (struct cmd_event *)client->mem_access;
	if (mem_access != NULL) {
		if (mem_access->state != MEM_DONE) {
			mem_access->resp = PSL_RESPONSE_FAILED;
			mem_access->state = MEM_DONE;
		}
	}
	client->mem_access = NULL;
	client->mmio_access = NULL;
	client->state = CLIENT_NONE;

	psl->attached_clients--;
	info_msg( "Detatched a client: current attached clients = %d\n", psl->attached_clients );

	// where do we *really* free the client struct and it's contents???
	
}

// See if AFU changed any of the aux2 signals and handle accordingly
int _handle_aux2(struct psl *psl, uint32_t * parity, uint32_t * latency,
		uint64_t * error)
{
        struct job *job;
	struct job_event *_prev;
	struct job_event *cacked_pe;
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
	uint64_t llcmd;
	uint64_t context;
	uint8_t ack = PSLSE_DETACH;

	job = psl->job;
	if (job == NULL)
		return 0;

	// See if AFU is driving AUX2 signal changes
	dbg_aux2 = reset = reset_complete = *error = 0;
	if (psl_get_aux2_change(job->afu_event, &job_running, &job_done,
				&job_cack_llcmd, &job_error, &job_yield,
				&tb_request, &par_enable, &read_latency) == PSL_SUCCESS) {
		// Handle job_done
		if (job_done) {
			debug_msg("%s:_handle_aux2: JOB done", job->afu_name);
			dbg_aux2 |= DBG_AUX2_DONE;
			*error = job_error;
		        //debug_msg("%s,%d:_handle_aux2, jerror is %x ", 
			//	  job->afu_name, job->dbg_id, job_error );
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
			debug_msg("%s:_handle_aux2: JOB running", job->afu_name);
			*(job->psl_state) = PSLSE_RUNNING;
			dbg_aux2 |= DBG_AUX2_RUNNING;
		}
		// Handle job cack llcmd
		if (job_cack_llcmd) {
		        // remove the current pending pe from the list
		        // loop through the pe's for the current pending one;
		        // copy its _next to _prev's _next
		        // remove the current pe
		        debug_msg("%s,%d:_handle_aux2, jcack, complete llcmd and remove pe", 
				  job->afu_name, job->dbg_id );
			cacked_pe = NULL;
			if (job->pe != NULL) {		  
			  if (job->pe->state == PSLSE_PENDING) {
			    // remove the first entry in the list
			    debug_msg("%s,%d:_handle_aux2, jcack, first pe is pending, job=0x%016"PRIx64", pe=0x%016"PRIx64, 
				      job->afu_name, job->dbg_id, job, job->pe );
			    cacked_pe = job->pe;
			    job->pe = job->pe->_next;
			  } else {
			    _prev = job->pe;
			    while (_prev->_next != NULL) {
			      debug_msg("%s,%d:_handle_aux2, jcack, looking for pending pe, _prev=0x%016"PRIx64", _next=0x%016"PRIx64, 
					job->afu_name, job->dbg_id, _prev, _prev->_next );
			      if (_prev->_next->state == PSLSE_PENDING) {
				// remove this entry in the list
				debug_msg("%s,%d:_handle_aux2, jcack, found pending pe, _next=0x%016"PRIx64, 
					job->afu_name, job->dbg_id, _prev->_next );
				cacked_pe = _prev->_next;
				_prev->_next = _prev->_next->_next;
			      } else {
				_prev = _prev->_next;
			      }
			    }
			  }
			}
			if (cacked_pe != NULL) {
			  // this is the pe that I want to "finish" processing
			  // get just the llcmd part of the addr
			  llcmd = cacked_pe->addr & PSL_LLCMD_MASK;
			  context = cacked_pe->addr & PSL_LLCMD_CONTEXT_MASK;
			  debug_msg("%s,%d:_handle_aux2: llcmd addr = 0x%016"PRIx64"; llcmd = 0x%016"PRIx64"; context = 0x%016"PRIx64, 
				    job->afu_name, job->dbg_id, cacked_pe->addr, llcmd, context);
			  switch ( llcmd ) {
			  case PSL_LLCMD_ADD:
			    // if it is a start, just keep going, print a message
			    debug_msg("%s,%d:_handle_aux2: LLCMD ADD acked", job->afu_name, job->dbg_id );
			    break;
			  case PSL_LLCMD_TERMINATE:
			    // if it is a terminate, make sure the cmd list is empty, warn if not empty
			    debug_msg("%s,%d:_handle_aux2: LLCMD TERMINATE acked", job->afu_name, job->dbg_id );
			    if ( _is_cmd_pending(psl, context) ) {
			      warn_msg( "%s,%d:AFU command for context %d still pending when LLCMD TERMINATE acked", 
					job->afu_name, job->dbg_id, context);
			    }
			    break;
			  case PSL_LLCMD_REMOVE:
			    // if it is a remove, send the detach response to the client and close up the client
			    debug_msg("%s,%d:_handle_aux2: LLCMD REMOVE acked", job->afu_name, job->dbg_id );
			    debug_msg("%s,%d:_handle_aux2: detach response sent to host on socket %d", 
				      job->afu_name, job->dbg_id, psl->client[context]->fd);
			    put_bytes(psl->client[context]->fd, 1, &ack,
			    	      psl->dbg_fp, psl->dbg_id,
			    	      psl->client[context]->context);
			    _free( psl, psl->client[context] );
			    psl->client[context] = NULL;  // I don't like this part...
			    break;
			  default:
			    debug_msg("%s,%d:_handle_aux2: acked llcmd %d did not match an LLCMD pe", 
				      job->afu_name, job->dbg_id, llcmd );
			    break;
			  }
			  debug_msg("%s,%d:_handle_aux2, jcack, free pe, addr=0x%016"PRIx64, 
				      job->afu_name, job->dbg_id, cacked_pe );
			  free( cacked_pe );
			} else {
			  debug_msg("%s,%d:_handle_aux2, jcack, no pe's to remove - why???", 
				    job->afu_name, job->dbg_id );	  
			}
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
			error_msg("_handle_aux2: ah_jdone & ah_jrunning asserted together");
		if ((read_latency != 1) && (read_latency != 3))
			warn_msg("_handle_aux2: ah_brlat must be either 1 or 3");
		*parity = par_enable;
		*latency = read_latency;

		// DEBUG
		debug_job_aux2(job->dbg_fp, job->dbg_id, dbg_aux2);
	}

	if (reset)
		add_job(job, PSL_JOB_RESET, 0L);

	return reset_complete;
}

// Handle events from AFU
static void _handle_afu(struct psl *psl)
{
	struct client *client;
	uint64_t error;
	uint8_t *buffer;
	int reset_done;
	int i;
	size_t size;

	reset_done = _handle_aux2(psl, &(psl->parity_enabled),
				 &(psl->latency), &error);
	if (error) {
	  if (dedicated_mode_support(psl->mmio)) {
		client = psl->client[0];
		size = 1 + sizeof(uint64_t);
		buffer = (uint8_t *) malloc(size);
		buffer[0] = PSLSE_AFU_ERROR;
		error = htonll(error);
		memcpy((char *)&(buffer[1]), (char *)&error, sizeof(error));
	        warn_msg("%s: Received JERROR: 0x%016"PRIx64" in afu-dedicated mode", psl->name, error);
		if (put_bytes
		    (client->fd, size, buffer, psl->dbg_fp, psl->dbg_id,
		     0) < 0) {
			client_drop(client, PSL_IDLE_CYCLES, CLIENT_NONE);
		}
	  }
	  if (directed_mode_support(psl->mmio)) {
	        // afu error gets logged by OS. - print warning message
                // no interrupt/event is sent up to the application - don't "put_bytes" back to client(s)
	        // all clients lose connection to afu but how is this observered by the client?
	        warn_msg("%s: Received JERROR: 0x%016"PRIx64" in afu-directed mode", psl->name, error);
		for (i = 0; i < psl->max_clients; i++) {
			if (psl->client[i] == NULL)
				continue;
			client_drop(psl->client[i], PSL_IDLE_CYCLES, CLIENT_NONE);
		}
	  }
	}
	handle_mmio_ack(psl->mmio, psl->parity_enabled);
	if (psl->cmd != NULL) {
		if (reset_done)
			psl->cmd->credits = psl->cmd->parms->credits;
		handle_response(psl->cmd);
		handle_buffer_write(psl->cmd);
		handle_buffer_read(psl->cmd);
		handle_buffer_data(psl->cmd, psl->parity_enabled);
		handle_mem_write(psl->cmd);
		handle_touch(psl->cmd);
		handle_cmd(psl->cmd, psl->parity_enabled, psl->latency);
		handle_interrupt(psl->cmd);
	}
}

static void _handle_client(struct psl *psl, struct client *client)
{
	struct mmio_event *mmio;
	struct cmd_event *cmd;
	uint8_t buffer[MAX_LINE_CHARS];
	int dw = 0;
	int eb_rd = 0;

	// Handle MMIO done
	if (client->mmio_access != NULL) {
		client->idle_cycles = PSL_IDLE_CYCLES;
		client->mmio_access = handle_mmio_done(psl->mmio, client);
	}
	// Client disconnected
	if (client->state == CLIENT_NONE)
		return;

	// Check for event from application
	cmd = (struct cmd_event *)client->mem_access;
	mmio = NULL;
	if (bytes_ready(client->fd, 1, &(client->abort))) {
		if (get_bytes(client->fd, 1, buffer, psl->timeout,
			      &(client->abort), psl->dbg_fp, psl->dbg_id,
			      client->context) < 0) {
			client_drop(client, PSL_IDLE_CYCLES, CLIENT_NONE);
			return;
		}
		switch (buffer[0]) {
		case PSLSE_DETACH:
		        debug_msg("DETACH request from client context %d on socket %d", client->context, client->fd);
		        //client_drop(client, PSL_IDLE_CYCLES, CLIENT_NONE);
		        _detach(psl, client);
			break;
		case PSLSE_ATTACH:
			_attach(psl, client);
			break;
		case PSLSE_MEM_FAILURE:
			if (client->mem_access != NULL)
				handle_aerror(psl->cmd, cmd);
			client->mem_access = NULL;
			break;
		case PSLSE_MEM_SUCCESS:
			if (client->mem_access != NULL)
				handle_mem_return(psl->cmd, cmd, client->fd);
			client->mem_access = NULL;
			break;
		case PSLSE_MMIO_MAP:
			handle_mmio_map(psl->mmio, client);
			break;
		case PSLSE_MMIO_WRITE64:
			dw = 1;
		case PSLSE_MMIO_WRITE32:	/*fall through */
			mmio = handle_mmio(psl->mmio, client, 0, dw, 0);
			break;
		case PSLSE_MMIO_EBREAD:
                        eb_rd = 1;
		case PSLSE_MMIO_READ64: /*fall through */
			dw = 1;
		case PSLSE_MMIO_READ32:	/*fall through */
			mmio = handle_mmio(psl->mmio, client, 1, dw, eb_rd);
			break;
		default:
		  error_msg("Unexpected 0x%02x from client on socket", buffer[0], client->fd);
		}

		if (mmio)
			client->mmio_access = (void *)mmio;

		if (client->state == CLIENT_VALID)
			client->idle_cycles = PSL_IDLE_CYCLES;
	}
}

// PSL thread loop
static void *_psl_loop(void *ptr)
{
	struct psl *psl = (struct psl *)ptr;
	struct cmd_event *event, *temp;
	int events, i, stopped, reset;
	uint8_t ack = PSLSE_DETACH;

	stopped = 1;
	pthread_mutex_lock(psl->lock);
	while (psl->state != PSLSE_DONE) {
		// idle_cycles continues to generate clock cycles for some
		// time after the AFU has gone idle.  Eventually clocks will
		// not be presented to an idle AFU to keep simulation
		// waveforms from getting huge with no activity cycles.
		if (psl->state != PSLSE_IDLE) {
			psl->idle_cycles = PSL_IDLE_CYCLES;
			if (stopped)
				info_msg("Clocking %s", psl->name);
			fflush(stdout);
			stopped = 0;
		}

		if (psl->idle_cycles) {
			// Clock AFU
			psl_signal_afu_model(psl->afu_event);
			// Check for events from AFU
			events = psl_get_afu_events(psl->afu_event);

			// Error on socket
			if (events < 0) {
				warn_msg("Lost connection with AFU");
				break;
			}
			// Handle events from AFU
			if (events > 0)
				_handle_afu(psl);

			// Drive events to AFU
			send_job(psl->job);
			send_pe(psl->job);
			send_mmio(psl->mmio);

			if (psl->mmio->list == NULL)
				psl->idle_cycles--;
		} else {
			if (!stopped)
				info_msg("Stopping clocks to %s", psl->name);
			stopped = 1;
			lock_delay(psl->lock);
		}

		// Skip client section if AFU descriptor hasn't been read yet
		if (psl->client == NULL) {
			lock_delay(psl->lock);
			continue;
		}
		// Check for event from application
		reset = 0;
		for (i = 0; i < psl->max_clients; i++) {
			if (psl->client[i] == NULL)
				continue;
			if ((psl->client[i]->type == 'd') && 
			    (psl->client[i]->state == CLIENT_NONE) &&
			    (psl->client[i]->idle_cycles == 0)) {
			        // this was the old way of detaching a dedicated process app/afu pair
			        // we get the detach message, drop the client, and wait for idle cycle to get to 0
				put_bytes(psl->client[i]->fd, 1, &ack,
					  psl->dbg_fp, psl->dbg_id,
					  psl->client[i]->context);
				_free(psl, psl->client[i]);
				psl->client[i] = NULL;  // aha - this is how we only called _free once the old way
				                        // why do we not free client[i]?
				                        // because this was a short cut pointer
				                        // the *real* client point is in client_list in pslse
				reset = 1;
				// for m/s devices we need to do this differently and not send a reset...
				// _handle_client - creates the llcmd's to term and remove
				// send_pe - sends the llcmd pe's to afu one at a time
				// _handle_afu calls _handle_aux2
				// _handle_aux2 finishes the llcmd pe's when jcack is asserted by afu
				//   when the remove llcmd is processed, we should put_bytes, _free and set client[i] to NULL
				continue;
			}
			if (psl->state == PSLSE_RESET)
				continue;
			_handle_client(psl, psl->client[i]);
			if (psl->client[i]->idle_cycles) {
				psl->client[i]->idle_cycles--;
			}
			if (client_cmd(psl->cmd, psl->client[i])) {
				psl->client[i]->idle_cycles = PSL_IDLE_CYCLES;
			}
		}

		// Send reset to AFU
		if (reset == 1) {
			psl->cmd->buffer_read = NULL;
			event = psl->cmd->list;
			while (event != NULL) {
				if (reset) {
					warn_msg
					    ("Client dropped context before AFU completed");
					reset = 0;
				}
				info_msg("Dumping command tag=0x%02x",
					 event->tag);
				if (event->data) {
					free(event->data);
				}
				if (event->parity) {
					free(event->parity);
				}
				temp = event;
				event = event->_next;
				free(temp);
			}
			psl->cmd->list = NULL;
			info_msg("Sending reset to AFU");
			add_job(psl->job, PSL_JOB_RESET, 0L);
		}

		lock_delay(psl->lock);
	}

	// Disconnect clients
	for (i = 0; i < psl->max_clients; i++) {
		if ((psl->client != NULL) && (psl->client[i] != NULL)) {
			// FIXME: Send warning to clients first?
			info_msg("Disconnecting %s context %d", psl->name,
				 psl->client[i]->context);
			close_socket(&(psl->client[i]->fd));
		}
	}

	// DEBUG
	debug_afu_drop(psl->dbg_fp, psl->dbg_id);

	// Disconnect from simulator, free memory and shut down thread
	info_msg("Disconnecting %s @ %s:%d", psl->name, psl->host, psl->port);
	if (psl->client)
		free(psl->client);
	if (psl->_prev)
		psl->_prev->_next = psl->_next;
	if (psl->_next)
		psl->_next->_prev = psl->_prev;
	if (psl->cmd) {
		free(psl->cmd);
	}
	if (psl->job) {
		free(psl->job);
	}
	if (psl->mmio) {
		free(psl->mmio);
	}
	if (psl->host)
		free(psl->host);
	if (psl->afu_event) {
		psl_close_afu_event(psl->afu_event);
		free(psl->afu_event);
	}
	if (psl->name)
		free(psl->name);
	if (*(psl->head) == psl)
		*(psl->head) = psl->_next;
	pthread_mutex_unlock(psl->lock);
	free(psl);
	pthread_exit(NULL);
}

// Initialize and start PSL thread
//
// The return value is encode int a 16-bit value divided into 4 for each
// possible adapter.  Then the 4 bits in each adapter represent the 4 possible
// AFUs on an adapter.  For example: afu0.0 is 0x8000 and afu3.0 is 0x0008.
uint16_t psl_init(struct psl **head, struct parms *parms, char *id, char *host,
		  int port, pthread_mutex_t * lock, FILE * dbg_fp)
{
	struct psl *psl;
	struct job_event *reset;
	uint16_t location;

	location = 0x8000;
	if ((psl = (struct psl *)calloc(1, sizeof(struct psl))) == NULL) {
		perror("malloc");
		error_msg("Unable to allocation memory for psl");
		goto init_fail;
	}
	psl->timeout = parms->timeout;
	if ((strlen(id) != 6) || strncmp(id, "afu", 3) || (id[4] != '.')) {
		warn_msg("Invalid afu name: %s", id);
		goto init_fail;
	}
	if ((id[3] < '0') || (id[3] > '3')) {
		warn_msg("Invalid afu major: %c", id[3]);
		goto init_fail;
	}
	if ((id[5] < '0') || (id[5] > '3')) {
		warn_msg("Invalid afu minor: %c", id[5]);
		goto init_fail;
	}
	psl->dbg_fp = dbg_fp;
	psl->major = id[3] - '0';
	psl->minor = id[5] - '0';
	psl->dbg_id = psl->major << 4;
	psl->dbg_id |= psl->minor;
	location >>= (4 * psl->major);
	location >>= psl->minor;
	if ((psl->name = (char *)malloc(strlen(id) + 1)) == NULL) {
		perror("malloc");
		error_msg("Unable to allocation memory for psl->name");
		goto init_fail;
	}
	strcpy(psl->name, id);
	if ((psl->host = (char *)malloc(strlen(host) + 1)) == NULL) {
		perror("malloc");
		error_msg("Unable to allocation memory for psl->host");
		goto init_fail;
	}
	strcpy(psl->host, host);
	psl->port = port;
	psl->client = NULL;
	psl->idle_cycles = PSL_IDLE_CYCLES;
	psl->lock = lock;

	// Connect to AFU
	psl->afu_event = (struct AFU_EVENT *)malloc(sizeof(struct AFU_EVENT));
	if (psl->afu_event == NULL) {
		perror("malloc");
		goto init_fail;
	}
	info_msg("Attempting to connect AFU: %s @ %s:%d", psl->name,
		 psl->host, psl->port);
	if (psl_init_afu_event(psl->afu_event, psl->host, psl->port) !=
	    PSL_SUCCESS) {
		warn_msg("Unable to connect AFU: %s @ %s:%d", psl->name,
			 psl->host, psl->port);
		goto init_fail;
	}
	// DEBUG
	debug_afu_connect(psl->dbg_fp, psl->dbg_id);

	// Initialize job handler
	debug_msg("%s @ %s:%d: job_init", psl->name, psl->host, psl->port);
	if ((psl->job = job_init(psl->afu_event, &(psl->state), psl->name,
				 psl->dbg_fp, psl->dbg_id)) == NULL) {
		perror("job_init");
		goto init_fail;
	}
	// Initialize mmio handler
	debug_msg("%s @ %s:%d: mmio_init", psl->name, psl->host, psl->port);
	if ((psl->mmio = mmio_init(psl->afu_event, psl->timeout, psl->name,
				   psl->dbg_fp, psl->dbg_id)) == NULL) {
		perror("mmio_init");
		goto init_fail;
	}
	// Initialize cmd handler
	debug_msg("%s @ %s:%d: cmd_init", psl->name, psl->host, psl->port);
	if ((psl->cmd = cmd_init(psl->afu_event, parms, psl->mmio,
				 &(psl->state), psl->name, psl->dbg_fp,
				 psl->dbg_id))
	    == NULL) {
		perror("cmd_init");
		goto init_fail;
	}
	// Load in VSEC data (read in from pslse.parms file)
	psl->vsec_caia_version = parms->caia_version;
	psl->vsec_psl_rev_level= parms->psl_rev_level;
	psl->vsec_image_loaded= parms->image_loaded;
	psl->vsec_base_image= parms->base_image;
	// Set credits for AFU
	if (psl_aux1_change(psl->afu_event, psl->cmd->credits) != PSL_SUCCESS) {
		warn_msg("Unable to set credits");
		goto init_fail;
	}
	// Start psl loop thread
	if (pthread_create(&(psl->thread), NULL, _psl_loop, psl)) {
		perror("pthread_create");
		goto init_fail;
	}
	// Add psl to list
	while ((*head != NULL) && ((*head)->major < psl->major)) {
		head = &((*head)->_next);
	}
	while ((*head != NULL) && ((*head)->major == psl->major) &&
	       ((*head)->minor < psl->minor)) {
		head = &((*head)->_next);
	}
	psl->_next = *head;
	if (psl->_next != NULL)
		psl->_next->_prev = psl;
	*head = psl;

	// Send reset to AFU
	debug_msg("%s @ %s:%d: Sending reset job.", psl->name, psl->host, psl->port);
	reset = add_job(psl->job, PSL_JOB_RESET, 0L);
	while (psl->job->job == reset) {	/*infinite loop */
		lock_delay(psl->lock);
	}

	// Read AFU descriptor
	debug_msg("%s @ %s:%d: Reading AFU descriptor.", psl->name, psl->host,
	          psl->port);
	psl->state = PSLSE_DESC;
	read_descriptor(psl->mmio, psl->lock);

	// Finish PSL configuration
	psl->state = PSLSE_IDLE;
	if (dedicated_mode_support(psl->mmio)) {
		// AFU supports Dedicated Mode
		psl->max_clients = 1;
	}
	if (directed_mode_support(psl->mmio)) {
		// AFU supports Directed Mode
		psl->max_clients = psl->mmio->desc.num_of_processes;
	}
	if (psl->max_clients == 0) {
		error_msg("AFU programming model is invalid");
		goto init_fail;
	}
	psl->client = (struct client **)calloc(psl->max_clients,
					       sizeof(struct client *));
	psl->cmd->client = psl->client;
	psl->cmd->max_clients = psl->max_clients;

	return location;

 init_fail:
	if (psl) {
		if (psl->afu_event) {
			psl_close_afu_event(psl->afu_event);
			free(psl->afu_event);
		}
		if (psl->host)
			free(psl->host);
		if (psl->name)
			free(psl->name);
		free(psl);
	}
	pthread_mutex_unlock(lock);
	return 0;
}
