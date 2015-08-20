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
#include <inttypes.h>
#include <malloc.h>
#include <poll.h>
#include <sys/types.h>

#include "mmio.h"
#include "psl.h"
#include "../common/debug.h"
#include "../common/psl_interface.h"

// Attach to AFU
static void _attach(struct psl *psl, struct client *client)
{
	uint64_t wed;
	uint8_t ack;
	uint8_t buffer[MAX_LINE_CHARS];
	size_t size;

	// FIXME: This only works for dedicate mode

	// Get wed value from application
	ack = PSLSE_DETACH;
	size = sizeof(uint64_t);
	if (get_bytes_silent(client->fd, size, buffer, psl->timeout,
			     &(client->abort)) < 0) {
		warn_msg("Failed to get WED value from client");
		client_drop(client, PSL_IDLE_CYCLES, CLIENT_NONE);
		goto attach_done;
	}
	memcpy((char *)&wed, (char *)buffer, sizeof(uint64_t));
	wed = le64toh(wed);

	// Send start to AFU
	if (add_job(psl->job, PSL_JOB_START, wed) != NULL) {
		psl->idle_cycles = PSL_IDLE_CYCLES;
		ack = PSLSE_ATTACH;
	}

 attach_done:
	if (put_bytes(client->fd, 1, &ack, psl->dbg_fp, psl->dbg_id,
		      client->context) < 0) {
		client_drop(client, PSL_IDLE_CYCLES, CLIENT_NONE);
	}
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
	if (client->job)
		client->job->state = PSLSE_DONE;
	client->state = CLIENT_NONE;
}

// Handle events from AFU
static void _handle_afu(struct psl *psl)
{
	struct client *client;
	uint64_t error;
	uint8_t *buffer;
	int reset_done;
	size_t size;

	reset_done = handle_aux2(psl->job, &(psl->parity_enabled),
				 &(psl->latency), &error);
	if (error && !directed_mode_support(psl->mmio)) {
		client = psl->client[0];
		size = 1 + sizeof(uint64_t);
		buffer = (uint8_t *) malloc(size);
		buffer[0] = PSLSE_AFU_ERROR;
		error = htole64(error);
		memcpy((char *)&(buffer[1]), (char *)&error, sizeof(error));
		if (put_bytes
		    (client->fd, size, buffer, psl->dbg_fp, psl->dbg_id,
		     0) < 0) {
			client_drop(client, PSL_IDLE_CYCLES, CLIENT_NONE);
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
			client_drop(client, PSL_IDLE_CYCLES, CLIENT_NONE);
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
			mmio = handle_mmio(psl->mmio, client, 0, dw);
			break;
		case PSLSE_MMIO_READ64:
			dw = 1;
		case PSLSE_MMIO_READ32:	/*fall through */
			mmio = handle_mmio(psl->mmio, client, 1, dw);
			break;
		default:
			error_msg("Unexpected 0x%02x from client", buffer[0]);
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
			if ((psl->client[i]->state == CLIENT_NONE) &&
			    (psl->client[i]->idle_cycles == 0)) {
				put_bytes(psl->client[i]->fd, 1, &ack,
					  psl->dbg_fp, psl->dbg_id,
					  psl->client[i]->context);
				_free(psl, psl->client[i]);
				psl->client[i] = NULL;
				reset = 1;
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
				warn_msg("Dumping command tag=0x%02x",
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
	if ((psl->job = job_init(psl->afu_event, &(psl->state), psl->dbg_fp,
				 psl->dbg_id)) == NULL) {
		perror("job_init");
		goto init_fail;
	}
	// Initialize mmio handler
	if ((psl->mmio = mmio_init(psl->afu_event, psl->timeout, psl->dbg_fp,
				   psl->dbg_id)) == NULL) {
		perror("mmio_init");
		goto init_fail;
	}
	// Initialize cmd handler
	if ((psl->cmd = cmd_init(psl->afu_event, parms, psl->mmio,
				 &(psl->state), psl->dbg_fp, psl->dbg_id))
	    == NULL) {
		perror("cmd_init");
		goto init_fail;
	}
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
	reset = add_job(psl->job, PSL_JOB_RESET, 0L);
	while (psl->job->job == reset) {	/*infinite loop */
		lock_delay(psl->lock);
	}

	// Read AFU descriptor
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
