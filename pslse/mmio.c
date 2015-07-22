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
 * Description: mmio.c
 *
 *  This file contains the code for MMIO access to the AFU including the
 *  AFU descriptor space.  Only one MMIO access is legal at a time.  So each
 *  client only tracks up to one mmio_access at a time.  However, since a
 *  "directed mode" AFU may have multiple clients attached the mmio struct
 *  tracks multiple mmio accesses with the element "list."  As MMIO requests
 *  are received from clients they are added to the list and handled in FIFO
 *  order.  The _add_event() function places each new MMIO event on the list
 *  as they are received from a client.  The psl code will periodically call
 *  send_mmio() which will drive the oldest pending MMIO event to the AFU.
 *  That event is put in PENDING state which blocks the PSL from sending any
 *  further MMIO until this MMIO event completes.  When the psl code detects
 *  the MMIO acknowledge it will call handle_mmio_ack().  This function moves
 *  the list head to the next event so that the next MMIO request can be sent.
 *  However, the event still lives and the client will still point to it.  When
 *  the psl code next calls handle_mmio_done for that client it will return the
 *  acknowledge as well as any data to the client.  At that point the event
 *  memory will be freed.
 */

#include <assert.h>
#include <inttypes.h>
#include <malloc.h>
#include <stdlib.h>

#include "../common/debug.h"
#include "mmio.h"

// Initialize MMIO tracking structure
struct mmio *mmio_init(struct AFU_EVENT *afu_event, int timeout, FILE * dbg_fp,
		       uint8_t dbg_id)
{
	struct mmio *mmio = (struct mmio *)calloc(1, sizeof(struct mmio));
	if (!mmio)
		return mmio;
	mmio->afu_event = afu_event;
	mmio->list = NULL;
	mmio->dbg_fp = dbg_fp;
	mmio->dbg_id = dbg_id;
	mmio->timeout = timeout;
	return mmio;
}

// Add new MMIO event
static struct mmio_event *_add_event(struct mmio *mmio, struct client *client,
				     uint32_t rnw, uint32_t dw, uint32_t addr,
				     uint32_t desc, uint64_t data)
{
	struct mmio_event *event;
	struct mmio_event **list;
	uint16_t context;

	// Add new event in IDLE state
	event = (struct mmio_event *)malloc(sizeof(struct mmio_event));
	if (!event)
		return event;
	event->rnw = rnw;
	event->dw = dw;
	event->addr = addr;
	event->desc = desc;
	event->data = data;
	event->state = PSLSE_IDLE;
	event->_next = NULL;

	// Add to end of list
	list = &(mmio->list);
	while (*list != NULL)
		list = &((*list)->_next);
	*list = event;
	if (desc)
		context = -1;
	else
		context = client->context;
	debug_mmio_add(mmio->dbg_fp, mmio->dbg_id, context, rnw, dw, addr);

	return event;
}

// Add AFU descriptor access event
static struct mmio_event *_add_desc(struct mmio *mmio, uint32_t rnw,
				    uint32_t dw, uint32_t addr, uint64_t data)
{
	return _add_event(mmio, NULL, rnw, dw, addr, 1, data);
}

// Add AFU MMIO (non-descriptor) access event
static struct mmio_event *_add_mmio(struct mmio *mmio, struct client *client,
				    uint32_t rnw, uint32_t dw, uint32_t addr,
				    uint64_t data)
{
	return _add_event(mmio, client, rnw, dw, addr, 0, data);
}

static void _wait_for_done(struct mmio *mmio, enum pslse_state *state,
			   pthread_mutex_t * lock)
{
	while (*state != PSLSE_DONE)	/* infinite loop */
		lock_delay(lock);
}

// Read the entire AFU descriptor and keep a copy
int read_descriptor(struct mmio *mmio, pthread_mutex_t * lock)
{
	struct mmio_event *event00, *event20, *event28, *event30, *event38,
	    *event40, *event48;

	// Queue mmio reads
	event00 = _add_desc(mmio, 1, 1, 0x00 >> 2, 0L);
	event20 = _add_desc(mmio, 1, 1, 0x20 >> 2, 0L);
	event28 = _add_desc(mmio, 1, 1, 0x28 >> 2, 0L);
	event30 = _add_desc(mmio, 1, 1, 0x30 >> 2, 0L);
	event38 = _add_desc(mmio, 1, 1, 0x38 >> 2, 0L);
	event40 = _add_desc(mmio, 1, 1, 0x40 >> 2, 0L);
	event48 = _add_desc(mmio, 1, 1, 0x48 >> 2, 0L);

	// Store data from reads
	_wait_for_done(mmio, &(event00->state), lock);
	mmio->desc.req_prog_model = (uint16_t) event00->data;
	mmio->desc.num_of_afu_CRs = (uint16_t) (event00->data >> 16);
	mmio->desc.num_of_processes = (uint16_t) (event00->data >> 32);
	mmio->desc.num_ints_per_process = (uint16_t) (event00->data >> 48);
	free(event00);

	_wait_for_done(mmio, &(event20->state), lock);
	mmio->desc.AFU_CR_len = event20->data;
	free(event20);

	_wait_for_done(mmio, &(event28->state), lock);
	mmio->desc.AFU_CR_offset = event28->data;
	free(event28);

	_wait_for_done(mmio, &(event30->state), lock);
	mmio->desc.PerProcessPSA = event30->data;
	free(event30);

	_wait_for_done(mmio, &(event38->state), lock);
	mmio->desc.PerProcessPSA_offset = event38->data;
	free(event38);

	_wait_for_done(mmio, &(event40->state), lock);
	mmio->desc.AFU_EB_len = event40->data;
	free(event40);

	_wait_for_done(mmio, &(event48->state), lock);
	mmio->desc.AFU_EB_offset = event48->data;
	free(event48);

	// Verify num_of_processes
	if (!mmio->desc.num_of_processes) {
		error_msg("AFU descriptor num_of_processes=0");
		errno = ENODEV;
		return -1;
	}
	// Verify req_prog_model
	if ((mmio->desc.req_prog_model & 0x7fffl) != 0x0010l) {
		error_msg("AFU descriptor: Unsupported req_prog_model");
		errno = ENODEV;
		return -1;
	}

	return 0;
}

// Send pending MMIO event to AFU
void send_mmio(struct mmio *mmio)
{
	struct mmio_event *event;

	event = mmio->list;

	// Check for valid event
	if ((event == NULL) || (event->state == PSLSE_PENDING))
		return;

	// Attempt to send mmio to AFU
	if (event->rnw && psl_mmio_read(mmio->afu_event, event->dw, event->addr,
					event->desc) == PSL_SUCCESS) {
		debug_mmio_send(mmio->dbg_fp, mmio->dbg_id, event->desc,
				event->rnw, event->dw, event->addr);
		event->state = PSLSE_PENDING;
	}
	if (!event->rnw && psl_mmio_write(mmio->afu_event, event->dw,
					  event->addr, event->data, event->desc)
	    == PSL_SUCCESS) {
		debug_mmio_send(mmio->dbg_fp, mmio->dbg_id, event->desc,
				event->rnw, event->dw, event->addr);
		event->state = PSLSE_PENDING;
	}
}

// Handle MMIO ack if returned by AFU
void handle_mmio_ack(struct mmio *mmio, uint32_t parity_enabled)
{
	uint64_t read_data;
	uint8_t parity;
	uint32_t read_data_parity;
	int rc;

	rc = psl_get_mmio_acknowledge(mmio->afu_event, &read_data,
				      &read_data_parity);
	if (rc == PSL_SUCCESS) {
		debug_mmio_ack(mmio->dbg_fp, mmio->dbg_id);
		if (!mmio->list || (mmio->list->state != PSLSE_PENDING)) {
			error_msg("Unexpected MMIO ack from AFU");
			return;
		}
		// Keep data for MMIO reads
		if (mmio->list->rnw) {
			if (parity_enabled) {
				parity = generate_parity(read_data, ODD_PARITY);
				if (read_data_parity != parity)
					error_msg
					    ("Parity error on MMIO read data");
			}
			mmio->list->data = read_data;
		}
		mmio->list->state = PSLSE_DONE;
		mmio->list = mmio->list->_next;
	}
}

// Handle MMIO map request from client
void handle_mmio_map(struct mmio *mmio, struct client *client)
{
	uint32_t flags;
	uint8_t ack = PSLSE_MMIO_ACK;
	int fd = client->fd;

	// Check for errors
	if (!(mmio->desc.PerProcessPSA & PSA_REQUIRED)) {
		warn_msg("Problem State Area Required bit not set");
		ack = PSLSE_MMIO_FAIL;
		goto map_done;
	}
	if (get_bytes_silent(fd, 4, (uint8_t *) & flags, mmio->timeout,
			     &(client->abort)) < 0) {
		client_drop(client, PSL_IDLE_CYCLES, CLIENT_NONE);
		warn_msg("Socket failure with client context %d",
			 client->context);
		ack = PSLSE_MMIO_FAIL;
		goto map_done;
	}
	// Check flags value and set
	if (!mmio->flags) {
		mmio->flags = le32toh(flags);
	} else if (mmio->flags != le32toh(flags)) {
		warn_msg("Set conflicting mmio endianess for AFU");
		ack = PSLSE_MMIO_FAIL;
	}

	if (ack == PSLSE_MMIO_ACK) {
		debug_mmio_map(mmio->dbg_fp, mmio->dbg_id, client->context);
	}

 map_done:
	// Send acknowledge to client
	if (put_bytes(fd, 1, &ack, mmio->dbg_fp, mmio->dbg_id, client->context)
	    < 0) {
		client_drop(client, PSL_IDLE_CYCLES, CLIENT_NONE);
	}
}

// Add mmio write event of register at offset to list
static struct mmio_event *_handle_mmio_write(struct mmio *mmio,
					     struct client *client, int dw)
{
	struct mmio_event *event;
	uint32_t offset;
	uint64_t data64;
	uint32_t data32;
	uint64_t data;
	int fd = client->fd;

	if (get_bytes_silent(fd, 4, (uint8_t *) & offset, mmio->timeout,
			     &(client->abort)) < 0) {
		goto write_fail;
	}
	offset = le32toh(offset);
	if (dw) {
		if (get_bytes_silent(fd, 8, (uint8_t *) & data64, mmio->timeout,
				     &(client->abort)) < 0) {
			goto write_fail;
		}
		// Convert data from client from little endian to host
		data = le64toh(data64);
	} else {
		if (get_bytes_silent(fd, 4, (uint8_t *) & data32, mmio->timeout,
				     &(client->abort)) < 0) {
			goto write_fail;
		}
		// Convert data from client from little endian to host
		data32 = le32toh(data32);
		data = (uint64_t) data32;
		data <<= 32;
		data |= (uint64_t) data32;
	}
	event = _add_mmio(mmio, client, 0, dw, offset / 4, data);
	return event;

 write_fail:
	// Socket connection is dead
	client_drop(client, PSL_IDLE_CYCLES, CLIENT_NONE);
	return NULL;
}

// Add mmio read event of register at offset to list
static struct mmio_event *_handle_mmio_read(struct mmio *mmio,
					    struct client *client, int dw)
{
	struct mmio_event *event;
	uint32_t offset;
	int fd = client->fd;

	if (get_bytes_silent(fd, 4, (uint8_t *) & offset, mmio->timeout,
			     &(client->abort)) < 0) {
		goto read_fail;
	}
	offset = le32toh(offset);
	event = _add_mmio(mmio, client, 1, dw, offset / 4, 0);
	return event;

 read_fail:
	// Socket connection is dead
	client_drop(client, PSL_IDLE_CYCLES, CLIENT_NONE);
	return NULL;
}

// Handle MMIO request from client
struct mmio_event *handle_mmio(struct mmio *mmio, struct client *client,
			       int rnw, int dw)
{
	uint8_t ack;

	// Only allow MMIO access when client is valid
	if (client->state != CLIENT_VALID) {
		ack = PSLSE_MMIO_FAIL;
		if (put_bytes(client->fd, 1, &ack, mmio->dbg_fp, mmio->dbg_id,
			      client->context) < 0) {
			client_drop(client, PSL_IDLE_CYCLES, CLIENT_NONE);
		}
		return NULL;
	}
	if (rnw)
		return _handle_mmio_read(mmio, client, dw);
	else
		return _handle_mmio_write(mmio, client, dw);
}

// Handle MMIO done
struct mmio_event *handle_mmio_done(struct mmio *mmio, struct client *client)
{
	struct mmio_event *event;
	uint8_t *buffer;
	int fd = client->fd;

	// Is there an MMIO event pending?
	event = (struct mmio_event *)client->mmio_access;
	if (event == NULL)
		return NULL;

	// MMIO event not done yet
	if (event->state != PSLSE_DONE)
		return event;

	if (event->rnw) {
		// Return acknowledge with read data
		if (event->dw) {
			buffer = (uint8_t *) malloc(9);
			buffer[0] = PSLSE_MMIO_ACK;
			memcpy(&(buffer[1]), &(event->data), 8);
			if (put_bytes(fd, 9, buffer, mmio->dbg_fp, mmio->dbg_id,
				      client->context) < 0) {
				client_drop(client, PSL_IDLE_CYCLES,
					    CLIENT_NONE);
			}
		} else {
			buffer = (uint8_t *) malloc(5);
			buffer[0] = PSLSE_MMIO_ACK;
			memcpy(&(buffer[1]), &(event->data), 4);
			if (put_bytes(fd, 5, buffer, mmio->dbg_fp, mmio->dbg_id,
				      client->context) < 0) {
				client_drop(client, PSL_IDLE_CYCLES,
					    CLIENT_NONE);
			}
		}
	} else {
		// Return acknowledge for write
		buffer = (uint8_t *) malloc(1);
		buffer[0] = PSLSE_MMIO_ACK;
		if (put_bytes(fd, 1, buffer, mmio->dbg_fp, mmio->dbg_id,
			      client->context) < 0) {
			client_drop(client, PSL_IDLE_CYCLES, CLIENT_NONE);
		}
	}
	debug_mmio_return(mmio->dbg_fp, mmio->dbg_id, client->context);
	free(event);
	free(buffer);

	return NULL;
}
