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

#include <arpa/inet.h>
#include <assert.h>
#include <inttypes.h>
#include <stdlib.h>

#include "../common/debug.h"
#include "mmio.h"

// Initialize MMIO tracking structure
struct mmio *mmio_init(struct AFU_EVENT *afu_event, int timeout, char *afu_name,
		       FILE * dbg_fp, uint8_t dbg_id)
{
	struct mmio *mmio = (struct mmio *)calloc(1, sizeof(struct mmio));
	if (!mmio)
		return mmio;
	mmio->afu_event = afu_event;
	mmio->list = NULL;
	mmio->afu_name = afu_name;
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
	if (client == NULL)  {
	  // don't try to recalculate the address
	  event->addr = addr;
	} else {
	  // adjust addr (aka offset) depending on type of device (client)
	  // type master/dedicated needs no adjustment - the address is the actual offset into the psa
	  // type slave needs to bump up to the per process problem state area and into the handles offset
	  // maybe I should put this up in add_mmio so the address calc is done and then shifted before callin _add_event...
	  switch (client->type) {
	  case 'd':
	  case 'm':
	    // addr has already been right shifted 2 bits.
	    event->addr = addr;
	    break;
	  case 's':
	    // the addr has already been shifted right 2 bits, need to also shift the mmio offset for this slave.
	    event->addr = (client->mmio_offset / 4) + addr;
	    break;
	  default:
	    // error
	    break;
	  }
	}
	// event->addr = addr;
	event->desc = desc;
	event->data = data;
	event->state = PSLSE_IDLE;
	event->_next = NULL;

	// debug the mmio and print the input address and the translated address
	// debug_msg("_add_event: %s: WRITE%d word=0x%05x (0x%05x) data=0x%s", 
	 debug_msg("_add_event:: WRITE word=0x%05x (0x%05x) data=0x%x", 
	 //	  mmio->afu_name, event->dw ? 64 : 32, 
	 	  event->addr, addr, event->data); 

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

static void _wait_for_done(enum pslse_state *state, pthread_mutex_t * lock)
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
	_wait_for_done(&(event00->state), lock);
	mmio->desc.req_prog_model = (uint16_t) event00->data & 0xffffl;
	mmio->desc.num_of_afu_CRs = (uint16_t) (event00->data >> 16) & 0xffffl;
	mmio->desc.num_of_processes =
	    (uint16_t) (event00->data >> 32) & 0xffffl;
	mmio->desc.num_ints_per_process =
	    (uint16_t) (event00->data >> 48) & 0xffffl;
	free(event00);

	_wait_for_done(&(event20->state), lock);
	mmio->desc.AFU_CR_len = event20->data;
	free(event20);

	_wait_for_done(&(event28->state), lock);
	mmio->desc.AFU_CR_offset = event28->data;
	free(event28);

	_wait_for_done(&(event30->state), lock);
	mmio->desc.PerProcessPSA = event30->data;
	free(event30);

	_wait_for_done(&(event38->state), lock);
	mmio->desc.PerProcessPSA_offset = event38->data;
	free(event38);

	_wait_for_done(&(event40->state), lock);
	mmio->desc.AFU_EB_len = event40->data;
	free(event40);

	_wait_for_done(&(event48->state), lock);
	mmio->desc.AFU_EB_offset = event48->data;
	free(event48);

	// Verify num_of_processes
	if (!mmio->desc.num_of_processes) {
		error_msg("AFU descriptor num_of_processes=0");
		errno = ENODEV;
		return -1;
	}
	// Verify req_prog_model
	if ( ( (mmio->desc.req_prog_model & 0x7fffl) != 0x0010 ) && // dedicated
	     ( (mmio->desc.req_prog_model & 0x7fffl) != 0x0004 ) && // afu-directed
	     ( (mmio->desc.req_prog_model & 0x7fffl) != 0x0014 ) ) {// both
		error_msg("AFU descriptor: Unsupported req_prog_model");
		errno = ENODEV;
		return -1;
	}

        // NEW BLOCK add code to check for CRs and read them in if available
        struct mmio_event *eventdevven, *eventclass;
        uint32_t crstart;
        uint16_t crnum = mmio->desc.num_of_afu_CRs;
        if ( crnum > 0) {
        crstart = mmio->desc.AFU_CR_offset;
        // allocate 
        struct config_record *cr_array = malloc(crnum * sizeof(struct config_record *));
        //struct config_record *crptr = &cr_array;
        mmio->desc.crptr = cr_array;
	// Queue mmio reads
	// Only do 32-bit mmio for config record data
	//eventdevven = _add_desc(mmio, 1, 1,crstart >> 2, 0L);
	eventdevven = _add_desc(mmio, 1, 0,crstart >> 2, 0L);
	//eventclass = _add_desc(mmio, 1, 1, (crstart+8) >> 2, 0L);
	eventclass = _add_desc(mmio, 1, 0, (crstart+8) >> 2, 0L);
	
	// Store data from reads
	_wait_for_done(&(eventdevven->state), lock);
	//debug_msg("XXXX: DATA: = %08x\n", eventdevven->data);
	//cr_array->cr_vendor = (uint16_t) (eventdevven->data >> 48) & 0xffffl;
	cr_array->cr_vendor = (uint16_t) (eventdevven->data >> 16);
	//cr_array->cr_device = (uint16_t) (eventdevven->data >> 32) 0xffffl;
	cr_array->cr_device = (uint16_t) (eventdevven->data );
        debug_msg("%x:%x CR dev & vendor", cr_array->cr_device, cr_array->cr_vendor);
        free(eventdevven);
        	debug_msg("%x:%x CR dev & vendor swapped", ntohs(cr_array->cr_device),ntohs(cr_array->cr_vendor));
        _wait_for_done(&(eventclass->state), lock);
	cr_array->cr_class = (uint32_t) (eventclass->data >> 32) & 0xffffffffl;
        free(eventclass);
        }
	else { /* always make a fake cr */
	struct config_record *cr_array = malloc(sizeof(struct config_record *));
	mmio->desc.crptr = cr_array;
	cr_array->cr_vendor = 0;
	cr_array->cr_device = 0;
	cr_array->cr_class = 0;
	}
        // end of NEW BLOCK`
	return 0;
}

// Send pending MMIO event to AFU
void send_mmio(struct mmio *mmio)
{
	struct mmio_event *event;
	char type[5];
	char data[17];

	event = mmio->list;

	// Check for valid event
	if ((event == NULL) || (event->state == PSLSE_PENDING))
		return;

	if (event->desc)
		sprintf(type, "DESC");
	else
		sprintf(type, "MMIO");

	// Attempt to send mmio to AFU
	if (event->rnw && psl_mmio_read(mmio->afu_event, event->dw, event->addr,
					event->desc) == PSL_SUCCESS) {
		debug_msg("%s:%s READ%d word=0x%05x", mmio->afu_name, type,
			  event->dw ? 64 : 32, event->addr);
		debug_mmio_send(mmio->dbg_fp, mmio->dbg_id, event->desc,
				event->rnw, event->dw, event->addr);
		event->state = PSLSE_PENDING;
	}
	if (!event->rnw && psl_mmio_write(mmio->afu_event, event->dw,
					  event->addr, event->data, event->desc)
	    == PSL_SUCCESS) {
		if (event->dw)
			sprintf(data, "%016" PRIx64, event->data);
		else
			sprintf(data, "%08" PRIx32, (uint32_t) event->data);
		debug_msg("%s:%s WRITE%d word=0x%05x data=0x%s",
			  mmio->afu_name, type, event->dw ? 64 : 32,
			  event->addr, data);
		debug_mmio_send(mmio->dbg_fp, mmio->dbg_id, event->desc,
				event->rnw, event->dw, event->addr);
		event->state = PSLSE_PENDING;
	}
}

// Handle MMIO ack if returned by AFU
void handle_mmio_ack(struct mmio *mmio, uint32_t parity_enabled)
{
	uint64_t read_data;
	uint32_t read_data_parity;
	uint8_t parity;
	int rc;
	char data[17];
	char type[5];

	rc = psl_get_mmio_acknowledge(mmio->afu_event, &read_data,
				      &read_data_parity);
	if (rc == PSL_SUCCESS) {
		debug_mmio_ack(mmio->dbg_fp, mmio->dbg_id);
		if (!mmio->list || (mmio->list->state != PSLSE_PENDING)) {
			warn_msg("Unexpected MMIO ack from AFU");
			return;
		}
		if (mmio->list->desc)
			sprintf(type, "DESC");
		else
			sprintf(type, "MMIO");
		if (mmio->list->rnw) {
			if (mmio->list->dw) {
				sprintf(data, "%016" PRIx64, read_data);
			} else {
				sprintf(data, "%08" PRIx32,
					(uint32_t) read_data);
			}
			debug_msg("%s:%s ACK data=0x%s", mmio->afu_name, type,
				  data);
		} else {
			debug_msg("%s:%s ACK", mmio->afu_name, type);
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
	        debug_msg("%s:handle_mmio_map failed context=%d",
			  mmio->afu_name, client->context);
		client_drop(client, PSL_IDLE_CYCLES, CLIENT_NONE);
		warn_msg("Socket failure with client context %d",
			 client->context);
		ack = PSLSE_MMIO_FAIL;
		goto map_done;
	}
	// Check flags value and set
	if (!mmio->flags) {
		mmio->flags = ntohl(flags);
	} else if (mmio->flags != ntohl(flags)) {
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
	offset = ntohl(offset);
	if (dw) {
		if (get_bytes_silent(fd, 8, (uint8_t *) & data64, mmio->timeout,
				     &(client->abort)) < 0) {
			goto write_fail;
		}
		// Convert data from client from little endian to host
		data = ntohll(data64);
	} else {
		if (get_bytes_silent(fd, 4, (uint8_t *) & data32, mmio->timeout,
				     &(client->abort)) < 0) {
			goto write_fail;
		}
		// Convert data from client from little endian to host
		data32 = ntohl(data32);
		data = (uint64_t) data32;
		data <<= 32;
		data |= (uint64_t) data32;
	}
	event = _add_mmio(mmio, client, 0, dw, offset / 4, data);
	return event;

 write_fail:
	// Socket connection is dead
	debug_msg("%s:_handle_mmio_write failed context=%d",
		  mmio->afu_name, client->context);
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
	offset = ntohl(offset);
	event = _add_mmio(mmio, client, 1, dw, offset / 4, 0);
	return event;

 read_fail:
	// Socket connection is dead
	debug_msg("%s:_handle_mmio_read failed context=%d",
		  mmio->afu_name, client->context);
	client_drop(client, PSL_IDLE_CYCLES, CLIENT_NONE);
	return NULL;
}

// Add mmio read event of error buffer at offset to list
static struct mmio_event *_handle_mmio_read_eb(struct mmio *mmio,
					    struct client *client, int dw)
{
	struct mmio_event *event;
	uint32_t offset;
	int fd = client->fd;

	if (get_bytes_silent(fd, 4, (uint8_t *) & offset, mmio->timeout,
			     &(client->abort)) < 0) {
		goto read_fail;
	}
	offset = ntohl(offset);
        offset = offset + (uint32_t)mmio->desc.AFU_EB_offset;
        debug_msg("offset for eb read is %x\n", offset);
//	event = _add_event(mmio, client, 1, dw, offset>>2, 1, 0);
	event = _add_desc(mmio, 1, dw, offset>>2, 0);
//        _wait_for_done(&(event->state), psl->lock);
	return event;

 read_fail:
	// Socket connection is dead
	debug_msg("%s:_handle_mmio_read failed context=%d",
		  mmio->afu_name, client->context);
	client_drop(client, PSL_IDLE_CYCLES, CLIENT_NONE);
	return NULL;
}


// Handle MMIO request from client
struct mmio_event *handle_mmio(struct mmio *mmio, struct client *client,
			       int rnw, int dw, int eb_rd)
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

	if (eb_rd) 
		return _handle_mmio_read_eb(mmio, client, dw);

	if (rnw)
		return _handle_mmio_read(mmio, client, dw);
	else
		return _handle_mmio_write(mmio, client, dw);
}

// Handle MMIO done
struct mmio_event *handle_mmio_done(struct mmio *mmio, struct client *client)
{
	struct mmio_event *event;
	uint64_t data64;
	uint32_t data32;
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
			data64 = htonll(event->data);
			memcpy(&(buffer[1]), &data64, 8);
			if (put_bytes(fd, 9, buffer, mmio->dbg_fp, mmio->dbg_id,
				      client->context) < 0) {
				client_drop(client, PSL_IDLE_CYCLES,
					    CLIENT_NONE);
			}
		} else {
			buffer = (uint8_t *) malloc(5);
			buffer[0] = PSLSE_MMIO_ACK;
			data32 = htonl(event->data);
			memcpy(&(buffer[1]), &data32, 4);
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

int dedicated_mode_support(struct mmio *mmio)
{
	return ((mmio->desc.req_prog_model & PROG_MODEL_MASK) ==
		PROG_MODEL_DEDICATED);
}

int directed_mode_support(struct mmio *mmio)
{
	return ((mmio->desc.req_prog_model & PROG_MODEL_MASK) ==
		PROG_MODEL_DIRECTED);
}
