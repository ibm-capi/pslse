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

#include <assert.h>
#include <endian.h>
#include <inttypes.h>
#include <malloc.h>
#include <poll.h>

#include "mmio.h"
#include "psl.h"
#include "../common/debug.h"
#include "../common/psl_interface.h"

// Attach to AFU
static void _attach(struct psl *psl, struct client* client)
{
	uint64_t wed;
	uint8_t ack;
	uint8_t buffer[MAX_LINE_CHARS];
	size_t size;
	int offset;

	// FIXME: This only works for dedicate mode

	// Get wed value from application
	ack = PSLSE_DETACH;
	size = 2*sizeof(uint64_t);
	if (get_bytes_silent(client->fd, size, buffer, psl->timeout,
			     &(client->abort)) < 0) {
		warn_msg("Failed to get WED value from client");
		client_drop(client, PSL_IDLE_CYCLES);
		goto attach_done;
	}
	memcpy((char*) &wed, (char*) buffer, sizeof(uint64_t));
	wed = le64toh(wed);
	offset = sizeof(uint64_t);
	memcpy((char*) &(client->page_size), (char*) &(buffer[offset]),
	       sizeof(uint64_t));
	client->page_size = le64toh(client->page_size);
	client->page_mask = client->page_size-1;
	client->page_mask = ~client->page_mask;

	// Send start to AFU
	if (add_job(psl->job, PSL_JOB_START, wed) != NULL) {
		psl->idle_cycles = PSL_IDLE_CYCLES;
		ack = PSLSE_ATTACH;
	}

attach_done:
	pthread_mutex_lock(&(psl->lock));
	if (put_bytes(client->fd, 1, &ack, psl->dbg_fp, psl->dbg_id,
		      client->context)<0) {
		client_drop(client, PSL_IDLE_CYCLES);
	}
	pthread_mutex_unlock(&(psl->lock));
}

// Client release from AFU
static void _free(struct psl *psl, struct client* client)
{
	struct cmd_event *mem_access;

	// DEBUG
        debug_context_remove(psl->dbg_fp, psl->dbg_id, client->context);

	info_msg("%s client disconnect from %s context %d", client->ip,
		 psl->name, client->context);
	pthread_mutex_lock(&(psl->lock));
	close(client->fd);
	client->fd = -1;
	client->idle_cycles = 0;
	if (client->ip)
		free(client->ip);
	client->ip = NULL;
	mem_access = (struct cmd_event *) client->mem_access;
	if (mem_access != NULL) {
		if (mem_access->state != MEM_DONE) {
			mem_access->resp = PSL_RESPONSE_AERROR;
			mem_access->state = MEM_DONE;
		}
	}
	client->mem_access = NULL;
	client->mmio_access = NULL;
	if (client->job)
		client->job->state = PSLSE_DONE;
	client->valid = 0;
	pthread_mutex_unlock(&(psl->lock));
}

// Handle events from AFU
static void _handle_afu(struct psl *psl)
{
	handle_aux2(psl->job, &(psl->parity_enabled), &(psl->latency));
	handle_mmio_ack(psl->mmio, psl->parity_enabled);
	if (psl->cmd != NULL) {
		handle_response(psl->cmd);
		handle_buffer_write(psl->cmd);
		handle_buffer_read(psl->cmd);
		handle_buffer_data(psl->cmd, psl->parity_enabled);
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

	// Handle MMIO done
	if (client->mmio_access != NULL) {
		client->idle_cycles = PSL_IDLE_CYCLES;
		client->mmio_access = handle_mmio_done(psl->mmio, client); 
	}

	// Check for event from application
	cmd = (struct cmd_event*) client->mem_access;
	mmio = NULL;
	if (bytes_ready(client->fd, &(client->abort))) {
		if (get_bytes(client->fd, 1, buffer, psl->timeout,
			      &(client->abort), psl->dbg_fp, psl->dbg_id,
			      client->context) < 0) {
			client_drop(client, PSL_IDLE_CYCLES);
			return;
		}
		switch (buffer[0]) {
		case PSLSE_DETACH:
			client_drop(client, PSL_IDLE_CYCLES);
			break;
		case PSLSE_ATTACH:
			_attach(psl, client);
			break;
		case PSLSE_MEM_FAILURE:
			if (client->mem_access != NULL) {
				handle_aerror(psl->cmd, cmd);
			}
			client->mem_access = NULL;
			break;
		case PSLSE_MEM_SUCCESS:
			if (client->mem_access != NULL) {
				handle_mem_return(psl->cmd, cmd, client->fd,
						  &(psl->lock));
			}
			client->mem_access = NULL;
			break;
		case PSLSE_MMIO_MAP:
			handle_mmio_map(psl->mmio, client);
			break;
		case PSLSE_MMIO_WRITE64:
			dw = 1;
		case PSLSE_MMIO_WRITE32:	/*fall through*/
			mmio = handle_mmio(psl->mmio, client, 0, dw);
			break;
		case PSLSE_MMIO_READ64:
			dw = 1;
		case PSLSE_MMIO_READ32:		/*fall through*/
			mmio = handle_mmio(psl->mmio, client, 1, dw);
			break;
		default:
			error_msg("Unexpected 0x%02x from client", buffer[0]);
		}

		if (mmio)
			client->mmio_access = (void*) mmio;

		client->idle_cycles = PSL_IDLE_CYCLES;
	}
}

// PSL thread loop
static void *_psl_loop(void *ptr)
{
	struct psl *psl = (struct psl*)ptr;
	struct cmd *cmd;
	struct cmd_event *event;
	struct cmd_event *oldest_event;
	char event_state[10];
	int events, i, stopped, reset, oldest_time, oldest_tag, last_tag;
	enum mem_state oldest_state;
	uint8_t ack = PSLSE_DETACH;

	oldest_tag = -1;
	last_tag = -1;
	oldest_time = 0;
	oldest_state = MEM_IDLE;
	oldest_event = NULL;
	stopped = 1;
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
			pthread_mutex_lock(&(psl->lock));
			// Clock AFU
			psl_signal_afu_model(psl->afu_event);
			// Check for events from AFU
			events = psl_get_afu_events(psl->afu_event);
			pthread_mutex_unlock(&(psl->lock));

			// Error on socket
			if (events < 0)
				break;

			// Handle events from AFU
			if (events > 0)
				_handle_afu(psl);

			// Drive events to AFU
			send_job(psl->job);
			send_mmio(psl->mmio);

			if ((psl->job->job==NULL) && (psl->mmio->list==NULL))
				psl->idle_cycles--;
		}
		else {
			if (!stopped)
				info_msg("Stopping clocks to %s", psl->name);
			fflush(stdout);
			stopped = 1;
			ns_delay(1000000);
		}

		// Skip client section if AFU descriptor hasn't been read yet
		if (psl->client == NULL)
			continue;

		// Check for event from application
		reset = 0;
		for (i = 0; i<psl->max_clients; i++) {
			if (psl->client[i] == NULL)
				continue;
			if ((psl->client[i]->valid < 0) &&
			    (psl->client[i]->idle_cycles == 0)) {
				pthread_mutex_lock(&(psl->lock));
				if (put_bytes(psl->client[i]->fd, 1, &ack,
					      psl->dbg_fp, psl->dbg_id,
					      psl->client[i]->context)<0) {
					client_drop(psl->client[i],
						    PSL_IDLE_CYCLES);
				}
				pthread_mutex_unlock(&(psl->lock));
				_free(psl, psl->client[i]);
				psl->client[i] = NULL;
				if (reset==0) {
					reset = 1;
				}
				continue;
			}
			if (psl->state == PSLSE_RESET) {
				continue;
			}
			if (psl->client[i]->valid > 0) {
				reset = -1;
				_handle_client(psl, psl->client[i]);
			}
			if (psl->client[i]->idle_cycles)
				psl->client[i]->idle_cycles--;
			if (client_cmd(psl->cmd, psl->client[i]))
				psl->client[i]->idle_cycles = PSL_IDLE_CYCLES;
		}

		// Check for lost commands
		cmd = psl->cmd;
		for (event=cmd->list; event!=NULL; event=event->_next) {
			if (event->tag == last_tag)
				break;
		}
		if (event==NULL)
			oldest_time = 0;
		for (i = 0; i<256; i++) {
			if (cmd->cmd_time[i]==0)
				continue;
			for (event=cmd->list; event!=NULL;
			     event=event->_next) {
				if (event->tag==i) {
					cmd->cmd_time[i]++;
					if (cmd->cmd_time[i]>oldest_time) {
						oldest_tag = i;
						oldest_time = cmd->cmd_time[i];
						oldest_state = event->state;
						oldest_event = event;
					}
					break;
				}
			}
			if (event==NULL) {
				error_msg("Lost tag=0x%02x", i);
			}
		}
		if ((oldest_event!=NULL) && ((oldest_tag!=last_tag) ||
		    (oldest_state!=oldest_event->state))) {
			oldest_state = oldest_event->state;
			last_tag = oldest_tag;
			switch(oldest_state) {
			case MEM_BUFFER:
				strcpy(event_state, "BUFFER");
				break;
			case MEM_REQUEST:
				strcpy(event_state, "REQUEST");
				break;
			case MEM_RECEIVED:
				strcpy(event_state, "RECEIVED");
				break;
			case MEM_DONE:
				strcpy(event_state, "DONE");
				break;
			default :
				strcpy(event_state, "IDLE");
			}
			info_msg("Oldest event tag=0x%02x state=%s age=%d",
				 oldest_tag, event_state, oldest_time);
		}

		// Send reset to AFU
		if (reset==1) {
			pthread_mutex_lock(&(psl->lock));
			psl->cmd->buffer_read = NULL;
			for (event=psl->cmd->list; event!=NULL;
			     event=event->_next) {
				if (reset) {
					warn_msg("Client dropped context before AFU completed");
					reset = 0;
				}
				warn_msg ("Dumping command tag=0x%02x",
					  event->tag);
				cmd->cmd_time[event->tag]=0;
				if (event->data) {
					free (event->data);
				}
				if (event->parity) {
					free (event->parity);
				}
				free(event);
			}
			psl->cmd->list = NULL;
			pthread_mutex_unlock(&(psl->lock));
			add_job(psl->job, PSL_JOB_RESET, 0L);
		}
	}

	// Disconnect clients
	for (i = 0; i< psl->max_clients; i++) {
		if ((psl->client != NULL) && (psl->client[i] != NULL)) {
			// FIXME: Send warning to clients first?
			info_msg("Disconnected %s context %d\n", psl->name,
				 psl->client[i]->context);
			close(psl->client[i]->fd);
		}
	}

	// DEBUG
	debug_afu_drop(psl->dbg_fp, psl->dbg_id);

	// Disconnect from simulator, free memory and shut down thread
	info_msg("Disconnected %s @ %s:%d\n", psl->name, psl->host, psl->port);
	pthread_mutex_destroy(&(psl->lock));
	if (psl->client)
		free(psl->client);
	if (psl->_prev)
		psl->_prev->_next = psl->_next;
	if (psl->_next)
		psl->_next->_prev = psl->_prev;
	if (psl->cmd) {
		pthread_mutex_destroy(&(psl->cmd->lock));
		free(psl->cmd);
	}
	if (psl->job) {
		pthread_mutex_destroy(&(psl->job->lock));
		free(psl->job);
	}
	if (psl->mmio) {
		pthread_mutex_destroy(&(psl->mmio->lock));
		free(psl->mmio);
	}
	if (psl->host)
		free(psl->host);
	if (psl->afu_event)
		free(psl->afu_event);
	if (psl->name)
		free(psl->name);
	if (*(psl->head) == psl)
		*(psl->head) = psl->_next;
	free(psl);
	pthread_exit(NULL);
}

// Initialize and start PSL thread
//
// The return value is encode int a 16-bit value divided into 4 for each
// possible adapter.  Then the 4 bits in each adapter represent the 4 possible
// AFUs on an adapter.  For example: afu0.0 is 0x8000 and afu3.0 is 0x0008.
uint16_t psl_init(struct psl **head, struct parms *parms, char* id, char* host,
		  int port, FILE *dbg_fp)
{
	struct psl *psl;
	struct job_event *reset;
	uint16_t location;

	location = 0x8000;
	if ((psl = (struct psl*) calloc(1, sizeof(struct psl))) == NULL) {
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
	if ((psl->name = (char *) malloc(strlen(id)+1)) == NULL) {
		perror("malloc");
		error_msg("Unable to allocation memory for psl->name");
		goto init_fail;
	}
	strcpy(psl->name, id);
	if ((psl->host = (char *) malloc(strlen(host)+1)) == NULL) {
		perror("malloc");
		error_msg("Unable to allocation memory for psl->host");
		goto init_fail;
	}
	strcpy(psl->host, host);
	psl->port = port;
	psl->client = NULL;
	psl->idle_cycles = PSL_IDLE_CYCLES;

	pthread_mutex_init(&(psl->lock), NULL);

	// Connect to AFU
	psl->afu_event = (struct AFU_EVENT *) malloc(sizeof(struct AFU_EVENT));
	if (psl->afu_event == NULL) {
		perror("malloc");
		goto init_fail_lock;
	}
	info_msg("Attempting to connect AFU: %s @ %s:%d", psl->name,
		  psl->host, psl->port);
	if (psl_init_afu_event(psl->afu_event, psl->host, psl->port) !=
	    PSL_SUCCESS) {
		warn_msg("Unable to connect AFU: %s @ %s:%d", psl->name,
			  psl->host, psl->port);
		goto init_fail_lock;
	}

	// DEBUG
	debug_afu_connect(psl->dbg_fp, psl->dbg_id);

	// Initialize job handler
	if ((psl->job = job_init(psl->afu_event, &(psl->lock), &(psl->state),
				 psl->dbg_fp, psl->dbg_id)) == NULL) {
		perror("job_init");
		goto init_fail_lock;
	}

	// Initialize mmio handler
	if ((psl->mmio = mmio_init(psl->afu_event, &(psl->lock), psl->timeout,
				   psl->dbg_fp, psl->dbg_id)) == NULL) {
		perror("mmio_init");
		goto init_fail_lock;
	}

	// Initialize cmd handler
	if ((psl->cmd = cmd_init(psl->afu_event, parms, psl->mmio,
				 &(psl->state), &(psl->lock), psl->dbg_fp,
				psl->dbg_id)) == NULL) {
		perror("cmd_init");
		goto init_fail_lock;
	}

	// Set credits for AFU
	if (psl_aux1_change(psl->afu_event, psl->cmd->credits) != PSL_SUCCESS) {
		warn_msg("Unable to set credits");
		goto init_fail_lock;
	}

	// Start psl loop thread
	if (pthread_create(&(psl->thread), NULL, _psl_loop, psl)) {
		perror("pthread_create");
		goto init_fail_lock;
	}

	// Add psl to list
	while ((*head != NULL) && ((*head)->major<psl->major)) {
		head = &((*head)->_next);
	}
	while ((*head != NULL) && ((*head)->major==psl->major) &&
               ((*head)->minor<psl->minor)) {
		head = &((*head)->_next);
	}
	psl->_next = *head;
	if (psl->_next != NULL)
		psl->_next->_prev = psl;
	*head = psl;

	// Send reset to AFU
	reset = add_job(psl->job, PSL_JOB_RESET, 0L);
	while (psl->job->job == reset) ns_delay(4); /*infinite loop*/

	// Read AFU descriptor
	psl->state = PSLSE_DESC;
	read_descriptor(psl->mmio);

	// Finish PSL configuration
	psl->state = PSLSE_IDLE;
	if ((psl->mmio->desc.req_prog_model & 0x7fffl) ==
	    PROG_MODEL_DEDICATED) {
		// Dedicated AFU
		psl->max_clients = 1;
	}
	if ((psl->mmio->desc.req_prog_model & 0x7fffl) ==
	    PROG_MODEL_DIRECTED) {
		// Dedicated AFU
		psl->max_clients = psl->mmio->desc.num_of_processes;
	}
	if (psl->max_clients == 0) {
		error_msg("AFU programming model is invalid");
		goto init_fail_lock;
	}
	psl->client = (struct client**)calloc(psl->max_clients,
					      sizeof(struct client*));
	psl->cmd->client = psl->client;

	return location;

init_fail_lock:
	pthread_mutex_destroy(&(psl->lock));
init_fail:
	if (psl) {
		if (psl->afu_event)
			free(psl->afu_event);
		if (psl->host)
			free(psl->host);
		if (psl->name)
			free(psl->name);
		free(psl);
	}
	return 0;
}
