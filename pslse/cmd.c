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
 * Description: cmd.c
 *
 *  This file contains the code for handling commands from the AFU.  This
 *  includes parity checking the command, generating buffer writes or reads as
 *  well as the final response for the command.  The handle_cmd() function is
 *  periodically called by psl code.  If a command is received from the AFU
 *  then parity and credits check will occur to see if the command is valid.
 *  If those checks pass then _parse_cmd() is called to determine the command
 *  type.  Depending on command type either _add_interrupt(), _add_touch(),
 *  _add_unlock(), _add_read(), _add_write() or _add_other() will be called to
 *  format the tracking event properly.  Each of these functions calls
 *  _add_cmd() which will randomly insert the command in the list.
 *
 *  Once an event is in the list then the event will be service in random order
 *  by the periodic calling by psl code of the functions: handle_interrupt(),
 *  handle_response(), handle_buffer_write(), handle_buffer_read(),
 *  handle_buffer_data() and handle_touch().  The state field is used to track
 *  the progress of each event until is fully completed and removed from the
 *  list completely.
 */

#include <assert.h>
#include <endian.h>
#include <inttypes.h>
#include <malloc.h>
#include <stdlib.h>

#include "cmd.h"
#include "mmio.h"
#include "../common/debug.h"
#include "../common/utils.h"

#define IRQ_MASK       0x00000000000007FFL
#define CACHELINE_MASK 0xFFFFFFFFFFFFFF80L

// Initialize cmd structure for tracking AFU command activity
struct cmd *cmd_init(struct AFU_EVENT *afu_event, struct parms* parms,
		     struct mmio *mmio, volatile enum pslse_state *state,
		     pthread_mutex_t *lock, FILE *dbg_fp, uint8_t dbg_id)
{
	struct cmd *cmd = (struct cmd*) calloc(1, sizeof(struct cmd));

	if (!cmd) {
		perror("malloc");
		exit(-1);
	}

	cmd->afu_event = afu_event;
	cmd->mmio = mmio;
	cmd->parms = parms;
	cmd->psl_state = state;
	cmd->psl_lock = lock;
	pthread_mutex_init(&(cmd->lock), NULL);
	cmd->credits = parms->credits;
	cmd->dbg_fp = dbg_fp;
	cmd->dbg_id = dbg_id;

	return cmd;
}

static void _print_event(struct cmd_event *event)
{
	printf("Command event: ");
	switch (event->type) {
	case CMD_READ:
		printf("READ");
		break;
	case CMD_WRITE:
		printf("WRITE");
		break;
	case CMD_TOUCH:
		printf("TOUCH");
		break;
	case CMD_INTERRUPT:
		printf("INTERRUPT");
		break;
	default:
		printf("OTHER");
	}
	printf(" tag=%02x", event->tag);
	printf(" context=%d", event->context);
	printf(" addr=0x%016"PRIx64, event->addr);
	printf(" size=0x%x\n\t", event->size);
	switch (event->state) {
	case MEM_BUFFER:
		printf("BUFFER");
		break;
	case MEM_REQUEST:
		printf("REQUEST");
		break;
	case MEM_RECEIVED:
		printf("RECEIVED");
		break;
	case MEM_DONE:
		printf("DONE");
		break;
	default:
		printf("IDLE");
	}
	printf(" Resp=0x%x Unlock=%d Restart=%d\n", event->resp,
	       event->unlock, event->restart);
}

// Update all pending responses at once to new state
static void _update_pending_resps(struct cmd *cmd, uint32_t resp)
{
	struct cmd_event *event;
	event = cmd->list;
	while (event) {
		if (event->state == MEM_IDLE) {
			event->state = MEM_DONE;
			event->resp = resp;
			debug_cmd_update(cmd->dbg_fp, cmd->dbg_id, event->tag,
					 event->context, event->resp);
		}
		event = event->_next;
	}
}

// Add new command to list
static void _add_cmd(struct cmd *cmd, uint32_t context, uint32_t tag,
		     uint32_t command, uint32_t abort, enum cmd_type type,
		     uint64_t addr, uint32_t size, enum mem_state state,
		     uint32_t resp, uint8_t unlock, uint8_t restart)
{
	struct cmd_event **head;
	struct cmd_event *event;

	event = (struct cmd_event*) calloc(1, sizeof(struct cmd_event));
	event->context = context;
	event->tag = tag;
	event->abt = abort;
	event->type = type;
	event->addr = addr;
	event->size = size;
	event->state = state;
	event->resp = resp;
	event->unlock = unlock;
	event->restart = restart;
	event->data = (uint8_t*)malloc(CACHELINE_BYTES);
	memset(event->data, 0xFF, CACHELINE_BYTES);
	event->parity = (uint8_t*)malloc(DWORDS_PER_CACHELINE/8);
	memset(event->parity, 0xFF, DWORDS_PER_CACHELINE/8);
	assert(cmd->cmd_time[tag]==0);
	cmd->cmd_time[tag]=1;

	pthread_mutex_lock(&(cmd->lock));
	head = &(cmd->list);
	while ((*head != NULL) && !allow_reorder(cmd->parms))
		head = &((*head)->_next);
	event->_next = *head;
	*head = event;
	debug_cmd_add(cmd->dbg_fp, cmd->dbg_id, tag, context, command);
	pthread_mutex_unlock(&(cmd->lock));
}

// Format and add interrupt to command list
static void _add_interrupt(struct cmd *cmd, uint32_t handle, uint32_t tag,
			   uint32_t command, uint32_t abort, uint16_t irq)
{
	uint32_t resp = PSL_RESPONSE_DONE;
	enum cmd_type type = CMD_INTERRUPT;

	if (!irq || (irq > cmd->client[handle]->max_irqs)) {
		warn_msg("AFU issued interrupt with illegal source id");
		resp = PSL_RESPONSE_FAILED;
		type = CMD_OTHER;
		goto int_done;
	}
	// Only track first interrupt until software reads event
	if (!cmd->irq)
		cmd->irq = irq;
int_done:
	_add_cmd(cmd, handle, tag, command, abort, type, (uint64_t) irq, 0,
		 MEM_DONE, resp, 0, 0);
}

// Format and add memory touch to command list
static void _add_touch(struct cmd *cmd, uint32_t handle, uint32_t tag,
		       uint32_t command, uint32_t abort, uint64_t addr,
		       uint8_t unlock)
{
	_add_cmd(cmd, handle, tag, command, abort, CMD_TOUCH, addr,
		 CACHELINE_BYTES, MEM_IDLE, PSL_RESPONSE_DONE, unlock, 0);
}

// Format and add unlock to command list
static void _add_unlock(struct cmd *cmd, uint32_t handle, uint32_t tag,
			uint32_t command, uint32_t abort)
{
	_add_cmd(cmd, handle, tag, command, abort, CMD_OTHER, 0, 0, MEM_DONE,
		 PSL_RESPONSE_DONE, 0, 0);
}

// Format and add memory read to command list
static void _add_read(struct cmd *cmd, uint32_t handle, uint32_t tag,
		      uint32_t command, uint32_t abort, uint64_t addr,
		      uint32_t size)
{
	// Reads will be added to the list and will next be processed
	// in the function handle_buffer_write()
	_add_cmd(cmd, handle, tag, command, abort, CMD_READ, addr, size,
		 MEM_IDLE, PSL_RESPONSE_DONE, 0, 0);
}

// Format and add memory write to command list
static void _add_write(struct cmd *cmd, uint32_t handle, uint32_t tag,
		       uint32_t command, uint32_t abort, uint64_t addr,
		       uint32_t size, uint8_t unlock)
{
	// Writes will be added to the list and will next be processed
	// in the function handle_buffer_read()
	_add_cmd(cmd, handle, tag, command, abort, CMD_WRITE, addr, size,
		 MEM_IDLE, PSL_RESPONSE_DONE, unlock, 0);
}

// Format and add misc. command to list
static void _add_other(struct cmd *cmd, uint32_t handle, uint32_t tag,
		       uint32_t command, uint32_t abort, uint32_t resp,
		       uint8_t restart)
{
	_add_cmd(cmd, handle, tag, command, abort, CMD_OTHER, 0, 0, MEM_DONE,
		 resp, 0, restart);
}

// Determine what type of command to add to list
static void _parse_cmd(struct cmd *cmd, uint32_t command, uint32_t tag,
		      uint64_t addr, uint32_t size, uint32_t abort,
		      uint32_t handle, uint32_t latency)
{
	uint16_t irq = (uint16_t) (addr & IRQ_MASK);
	uint8_t unlock = 0;
	if (handle >= cmd->mmio->desc.num_of_processes) {
		_add_other(cmd, handle, tag, command, abort,
			   PSL_RESPONSE_CONTEXT, 0);
		return;
	}
	switch (command) {
	// Interrupt
	case PSL_COMMAND_INTREQ:
		_add_interrupt(cmd, handle, tag, command, abort, irq);
		break;
	// Restart
	case PSL_COMMAND_RESTART:
		_add_other(cmd, handle, tag, command, abort, PSL_RESPONSE_DONE,
			   1);
		break;
	// Cacheline lock
	case PSL_COMMAND_LOCK:
		pthread_mutex_lock(&(cmd->lock));
		_update_pending_resps(cmd, PSL_RESPONSE_NLOCK);
		pthread_mutex_unlock(&(cmd->lock));
		cmd->locked = 1;
		cmd->lock_addr = addr & CACHELINE_MASK;
		_add_touch(cmd, handle, tag, command, abort, addr, 0);
		break;
	// Memory Reads
	case PSL_COMMAND_READ_CL_LCK:
		pthread_mutex_lock(&(cmd->lock));
		_update_pending_resps(cmd, PSL_RESPONSE_NLOCK);
		pthread_mutex_unlock(&(cmd->lock));
		cmd->locked = 1;
		cmd->lock_addr = addr & CACHELINE_MASK;
	case PSL_COMMAND_READ_CL_RES:	/*fall through*/
		if (!cmd->locked)
			cmd->res_addr = addr & CACHELINE_MASK;
	case PSL_COMMAND_READ_CL_NA:	/*fall through*/
	case PSL_COMMAND_READ_CL_S:	/*fall through*/
	case PSL_COMMAND_READ_CL_M:	/*fall through*/
	case PSL_COMMAND_READ_PNA:	/*fall through*/
	case PSL_COMMAND_READ_LS:	/*fall through*/
	case PSL_COMMAND_READ_LM:	/*fall through*/
	case PSL_COMMAND_RD_GO_S:	/*fall through*/
	case PSL_COMMAND_RD_GO_M:	/*fall through*/
	case PSL_COMMAND_RWITM:		/*fall through*/
		_add_read(cmd, handle, tag, command, abort, addr, size);
		break;
	// Cacheline unlock
	case PSL_COMMAND_UNLOCK:
		_add_unlock(cmd, handle, tag, command, abort);
		break;
	// Memory Writes
	case PSL_COMMAND_WRITE_UNLOCK:
		unlock = 1;
	case PSL_COMMAND_WRITE_C:	/*fall through*/
		if (!unlock)
			cmd->res_addr = 0L;
	case PSL_COMMAND_WRITE_MI:	/*fall through*/
	case PSL_COMMAND_WRITE_MS:	/*fall through*/
	case PSL_COMMAND_WRITE_NA:	/*fall through*/
	case PSL_COMMAND_WRITE_INJ:	/*fall through*/
	case PSL_COMMAND_WRITE_LM:	/*fall through*/
		if (!(latency % 2) || (latency > 3))
			error_msg("Write with invalid br_lat=%d", latency);
		_add_write(cmd, handle, tag, command, abort, addr, size,
			   unlock);
		break;
	// Treat these as memory touch to test for valid addresses
	case PSL_COMMAND_EVICT_I:
		if (cmd->locked && cmd->res_addr) {
			_add_other(cmd, handle, tag, command, abort,
				   PSL_RESPONSE_NRES, 0);
			break;
		}
	case PSL_COMMAND_PUSH_I:	/*fall through*/
	case PSL_COMMAND_PUSH_S:	/*fall through*/
		if (cmd->locked) {
			_add_other(cmd, handle, tag, command, abort,
				   PSL_RESPONSE_NLOCK, 0);
			break;
		}
	case PSL_COMMAND_TOUCH_I:
	case PSL_COMMAND_TOUCH_S:	/*fall through*/
	case PSL_COMMAND_TOUCH_M:	/*fall through*/
	case PSL_COMMAND_TOUCH_LS:	/*fall through*/
	case PSL_COMMAND_TOUCH_LM:	/*fall through*/
	case PSL_COMMAND_INVALIDATE:	/*fall through*/
	case PSL_COMMAND_CLAIM_M:	/*fall through*/
	case PSL_COMMAND_CLAIM_U:	/*fall through*/
		_add_touch(cmd, handle, tag, command, abort, addr, unlock);
		break;
	default:
		error_msg("Command currently unsupported 0x%04x", cmd);
		cmd->credits++;
		break;
	}
}

// Report parity error on some command bus
static void _cmd_parity_error(const char *msg, uint64_t value, uint8_t parity)
{
	error_msg("Command %s parity error 0x%04"PRIx64",%d", msg, value,
		  parity);
}

// Set flushing mode
static void _set_flush(struct cmd *cmd, struct cmd_event *event)
{
	struct flush_page *current;
	struct client *client;

	client = cmd->client[event->context];

	if (event->abt==ABORT_STRICT)
		client->flushing_strict = 1;

	if (event->abt==ABORT_PAGE) {
		current = (struct flush_page*)
				calloc(1, sizeof(struct flush_page));
		current->addr = event->addr & client->page_mask;
		current->_next = client->flushing_pages;
		client->flushing_pages = current;
	}
}

// Set flushing mode
static void _clear_flush(struct cmd *cmd, struct cmd_event *event)
{
	struct flush_page **current;
	struct flush_page *dead_man;
	struct client *client;
	uint64_t page;

	client = cmd->client[event->context];

	if (event->abt==ABORT_STRICT)
		cmd->client[event->context]->flushing_strict = 0;

	page = event->addr & client->page_mask;
	current = &(client->flushing_pages);
	while ((*current!=NULL) && (event->abt==ABORT_PAGE)) {
		if ((*current)->addr==page) {
			dead_man = *current;
			*current = dead_man->_next;
			free(dead_man);
		}
		else {
			current = &((*current)->_next);
		}
	}
}

// Will command flush?
static int _will_flush(struct client *client, uint64_t addr, uint64_t abt)
{
	struct flush_page *current;
	uint64_t page;

	if (client->flushing_strict && (abt==ABORT_STRICT))
		return 1;

	page = addr & client->page_mask;
	current = client->flushing_pages;
	while ((current!=NULL) && (abt==ABORT_PAGE)) {
		if (current->addr==page)
			return 1;
		current = current->_next;
	}

	return 0;
}

// See if a command was sent by AFU and process if so
void handle_cmd(struct cmd *cmd, uint32_t parity_enabled, uint32_t latency)
{
	struct cmd_event *event;
	uint64_t address, address_parity;
	uint32_t command, command_parity, tag, tag_parity, size, abort, handle;
	uint8_t parity, fail;
	int rc;

	pthread_mutex_lock(cmd->psl_lock);
	rc = psl_get_command(cmd->afu_event, &command, &command_parity, &tag,
			     &tag_parity, &address, &address_parity, &size,
			     &abort, &handle);
	pthread_mutex_unlock(cmd->psl_lock);
	if (rc == PSL_SUCCESS) {
		fail = 0;
		// Is AFU running?
		if (*(cmd->psl_state) != PSLSE_RUNNING) {
			warn_msg("Command without jrunning, tag=0x%02x", tag);
			fail = 1;
		}
		// Check parity
		if (parity_enabled) {
			parity = generate_parity(address, ODD_PARITY);
			if (parity != address_parity) {
				_cmd_parity_error("address", (uint64_t) address,
						  address_parity);
				fail = 1;
			}
			parity = generate_parity(tag, ODD_PARITY);
			if (parity != tag_parity) {
				_cmd_parity_error("tag", (uint64_t) tag,
						  tag_parity);
				fail = 1;
			}
			parity = generate_parity(command, ODD_PARITY);
			if (parity != command_parity) {
				_cmd_parity_error("code", (uint64_t) command,
						  command_parity);
				fail = 1;
			}
		}
		if (fail) {
			_add_other(cmd, handle, tag, command, abort,
				   PSL_RESPONSE_FAILED, 0);
		}
		// Check credits and parse
		if (!cmd->credits) {
			error_msg("AFU issued command without any credits");
			_add_other(cmd, handle, tag, command, abort,
				   PSL_RESPONSE_FAILED, 0);
		}
		else {
			cmd->credits--;
			if (cmd->client[handle] == NULL) {
				_add_other(cmd, handle, tag, command, abort,
					   PSL_RESPONSE_AERROR, 0);
				return;
			}
			if (_will_flush(cmd->client[handle], address, abort) &&
			    (command!=PSL_COMMAND_RESTART)) {
				_add_other(cmd, handle, tag, command, abort,
					   PSL_RESPONSE_FLUSHED, 0);
				return;
			}
			event = cmd->list;
			while (event!=NULL) {
				if (event->tag == tag) {
					error_msg("Duplicate tag 0x%02x", tag);
					return;
				}
				event = event->_next;
			}
			_parse_cmd(cmd, command, tag, address, size, abort,
				   handle, latency);
		}
	}
}

// Handle randomly selected pending read by either generating early buffer
// write with bogus data, send request to client for real data or do final
// buffer write with valid data after it has been received from client.
void handle_buffer_write(struct cmd *cmd)
{
	struct cmd_event *event = cmd->list;
	struct client *client;
	uint8_t buffer[10];
	uint64_t *addr;

	// Randomly select a pending read (or none)
	pthread_mutex_lock(&(cmd->lock));
	while (event != NULL) {
		if ((event->type == CMD_READ) &&
		    (event->state != MEM_DONE) &&
		    !allow_reorder(cmd->parms)) {
			break;
		}
		event = event->_next;
	}
	pthread_mutex_unlock(&(cmd->lock));
	if (event == NULL)
		return;

	client = cmd->client[event->context];
	if ((client == NULL) && (event->state != MEM_RECEIVED)) {
		event->resp = PSL_RESPONSE_AERROR;
		event->state = MEM_DONE;
		debug_cmd_update(cmd->dbg_fp, cmd->dbg_id, event->tag,
				 event->context, event->resp);
		return;
	}
	if ((event->state == MEM_IDLE) && !event->buffer_activity &&
	    allow_buffer(cmd->parms)) {
		// Buffer write with bogus data, but only once
		debug_cmd_buffer_write(cmd->dbg_fp, cmd->dbg_id, event->tag);
		pthread_mutex_lock(cmd->psl_lock);
		psl_buffer_write(cmd->afu_event, event->tag, event->addr,
				 CACHELINE_BYTES, event->data, event->parity);
		pthread_mutex_unlock(cmd->psl_lock);
		event->buffer_activity = 1;
	}
	else if ((event->state == MEM_IDLE) && (client->mem_access == NULL)) {
		if (allow_paged(cmd->parms)) {
			// Randomly cause paged response
			event->resp = PSL_RESPONSE_PAGED;
			event->state = MEM_DONE;
			debug_cmd_update(cmd->dbg_fp, cmd->dbg_id, event->tag,
					 event->context, event->resp);
		}
		else {
			// Send read request to client, set client->mem_access
			// to point to this event blocking any other memory
			// accesses to client until data is returned by call
			// to the _handle_mem_read() function.
			buffer[0] = (uint8_t) PSLSE_MEMORY_READ;
			buffer[1] = (uint8_t) event->size;
			addr = (uint64_t*) &(buffer[2]);
			*addr = htole64(event->addr);
			pthread_mutex_lock(cmd->psl_lock);
			event->abort = &(client->abort);
			if (put_bytes(client->fd, 10, buffer, cmd->dbg_fp,
				      cmd->dbg_id, event->context)<0) {
				client_drop(client, PSL_IDLE_CYCLES);
			}
			pthread_mutex_unlock(cmd->psl_lock);
			event->state = MEM_REQUEST;
			debug_cmd_client(cmd->dbg_fp, cmd->dbg_id, event->tag,
					 event->context);
			client->mem_access = (void *) event;
		}
	}
	if (event->state == MEM_RECEIVED) {
		// After the client returns data with a call to the function
		// _handle_mem_read() issue buffer write with valid data and
		// prepare for response.
		pthread_mutex_lock(cmd->psl_lock);
		if (psl_buffer_write(cmd->afu_event, event->tag, event->addr,
				     CACHELINE_BYTES, event->data,
				     event->parity) == PSL_SUCCESS) {
			event->resp = PSL_RESPONSE_DONE;
			event->state = MEM_DONE;
			debug_cmd_buffer_write(cmd->dbg_fp, cmd->dbg_id,
					       event->tag);
			debug_cmd_update(cmd->dbg_fp, cmd->dbg_id, event->tag,
					 event->context, event->resp);
		}
		pthread_mutex_unlock(cmd->psl_lock);
	}
}

// Handle randomly selected pending write
void handle_buffer_read(struct cmd *cmd)
{
	struct cmd_event *event = cmd->list;

	if (cmd->buffer_read != NULL)
		return;

	// Randomly select a pending write (or none)
	pthread_mutex_lock(&(cmd->lock));
	while (event != NULL) {
		if ((event->type == CMD_WRITE) &&
		    (event->state != MEM_DONE) &&
		    !allow_reorder(cmd->parms)) {
			break;
		}
		event = event->_next;
	}
	pthread_mutex_unlock(&(cmd->lock));
	if (event == NULL) {
		return;
	}

	if (event->state == MEM_IDLE) {
		// Randomly cause paged response
		if (allow_paged(cmd->parms)) {
			event->resp = PSL_RESPONSE_PAGED;
			event->state = MEM_DONE;
			debug_cmd_update(cmd->dbg_fp, cmd->dbg_id, event->tag,
					 event->context, event->resp);
			return;
		}
		// Send buffer read request to AFU.  Setting cmd->buffer_read
		// will block any more buffer read requests until buffer read
		// data is returned and handled in handle_buffer_data().
		pthread_mutex_lock(cmd->psl_lock);
		if (psl_buffer_read(cmd->afu_event, event->tag, event->addr,
				    CACHELINE_BYTES) == PSL_SUCCESS) {
			cmd->buffer_read = event;
			debug_cmd_buffer_read(cmd->dbg_fp, cmd->dbg_id,
					      event->tag);
			event->state = MEM_BUFFER;
		}
		pthread_mutex_unlock(cmd->psl_lock);
	}
}

// Handle randomly selected memory touch
void handle_touch(struct cmd *cmd)
{
	struct cmd_event *event = cmd->list;
	struct client *client;
	uint8_t buffer[10];
	uint64_t *addr;

	// Randomly select a pending touch (or none)
	pthread_mutex_lock(&(cmd->lock));
	while (event != NULL) {
		if ((event->type == CMD_TOUCH) &&
		    (event->state != MEM_DONE) &&
		    !allow_reorder(cmd->parms)) {
			break;
		}
		event = event->_next;
	}
	pthread_mutex_unlock(&(cmd->lock));
	if (event == NULL)
		return;

	client = cmd->client[event->context];

	// Abort if client disconnected
	if (client == NULL) {
		event->state = MEM_DONE;
		return;
	}

	// Abort if another memory access to client already in progress
	if(client->mem_access != NULL)
		return;

	// Randomly cause paged response
	if (allow_paged(cmd->parms)) {
		event->resp = PSL_RESPONSE_PAGED;
		event->state = MEM_DONE;
		debug_cmd_update(cmd->dbg_fp, cmd->dbg_id, event->tag,
				 event->context, event->resp);
		return;
	}
	// Send memory touch request to client
	buffer[0] = (uint8_t) PSLSE_MEMORY_TOUCH;
	buffer[1] = (uint8_t) event->size;
	addr = (uint64_t*) &(buffer[2]);
	*addr = htole64(event->addr & CACHELINE_MASK);
	pthread_mutex_lock(cmd->psl_lock);
	event->abort = &(client->abort);
	if (put_bytes(client->fd, 10, buffer, cmd->dbg_fp, cmd->dbg_id,
		      event->context)<0) {
		client_drop(client, PSL_IDLE_CYCLES);
	}
	pthread_mutex_unlock(cmd->psl_lock);
	debug_cmd_client(cmd->dbg_fp, cmd->dbg_id, event->tag, event->context);
	event->state = MEM_REQUEST;
	client->mem_access = (void *) event;
}

// Send pending interrupt to client as soon as possible
void handle_interrupt(struct cmd *cmd)
{
	struct cmd_event **head = &cmd->list;
	struct cmd_event *event;
	struct client *client;
	uint16_t irq;
	uint8_t buffer[3];

	// Send any interrupts to client immediately
	pthread_mutex_lock(&(cmd->lock));
	while (*head != NULL) {
		if ((*head)->type == CMD_INTERRUPT)
			break;
		head = &((*head)->_next);
	}
	event = *head;
	pthread_mutex_unlock(&(cmd->lock));

	if (event == NULL)
		return;

	// Send interrupt to client
	client = cmd->client[event->context];
	if (client == NULL) {
		event->resp = PSL_RESPONSE_FAILED;
		event->state = MEM_DONE;
		debug_cmd_update(cmd->dbg_fp, cmd->dbg_id, event->tag,
				 event->context, event->resp);
		return;
	}
	buffer[0] = PSLSE_INTERRUPT;
	irq = htole16(cmd->irq);
	memcpy(&(buffer[1]), &irq, 2);
	pthread_mutex_lock(cmd->psl_lock);
	event->abort = &(client->abort);
	if (put_bytes(client->fd, 3, buffer, cmd->dbg_fp, cmd->dbg_id,
		      event->context)<0) {
		client_drop(client, PSL_IDLE_CYCLES);
	}
	pthread_mutex_unlock(cmd->psl_lock);
	debug_cmd_client(cmd->dbg_fp, cmd->dbg_id, event->tag, event->context);
	event->state = MEM_DONE;
}

void handle_buffer_data(struct cmd *cmd, uint32_t parity_enable)
{
	struct client *client;
	uint64_t *addr;
	uint8_t *buffer, *data, *parity, *parity_check;
	uint64_t offset;
	int rc;

	// Has struct been initialized?
	if (cmd == NULL)
		return;

	pthread_mutex_lock(cmd->psl_lock);
	pthread_mutex_lock(&(cmd->lock));
	// Check if there is pending buffer read request
	if ((cmd->client == NULL) || (cmd->buffer_read == NULL)) {
		goto buffer_data_fail;
	}
	client = cmd->client[cmd->buffer_read->context];
	if (client == NULL) {
		cmd->buffer_read->resp = PSL_RESPONSE_AERROR;
		cmd->buffer_read->state = MEM_DONE;
		cmd->buffer_read = NULL;
		goto buffer_data_fail;
	}
	if (client->mem_access != NULL) {
		goto buffer_data_fail;
	}

	// Check if buffer read data has returned from AFU and if so
	// then send to client for memory write
	data = (uint8_t*)malloc(CACHELINE_BYTES);
	parity = (uint8_t*)malloc(DWORDS_PER_CACHELINE/8);
	rc = psl_get_buffer_read_data(cmd->afu_event, data, parity);
	if ((rc == PSL_SUCCESS) && (cmd->buffer_read != NULL) &&
	    (client->mem_access == NULL)) {
		if (parity_enable) {
			parity_check = (uint8_t*)malloc(DWORDS_PER_CACHELINE/8);
			generate_cl_parity(data, parity_check);
			if (strncmp((char *) parity, (char *) parity_check,
				    DWORDS_PER_CACHELINE/8)) {
				error_msg("Buffer read parity error tag=0x%02x",
					  cmd->buffer_read->tag);
			}
			free(parity_check);
		}
		// Randomly decide to not send data to client yet
		if (!cmd->buffer_read->buffer_activity &&
		    allow_buffer(cmd->parms)) {
			cmd->buffer_read->state = MEM_IDLE;
			cmd->buffer_read->buffer_activity = 1;
			cmd->buffer_read = NULL;
			goto buffer_data_done;
		}
		// Send data to client and clear cmd->buffer_read to allow
		// the next buffer read to occur.  The request will now await
		// confirmation from the client that the memory write was
		// successful before generating a response.  The client
		// response will cause a call to either handle_aerror() or
		// handle_mem_return().
		buffer = (uint8_t*)malloc(cmd->buffer_read->size+10);
		offset = cmd->buffer_read->addr & ~CACHELINE_MASK;
		buffer[0] = (uint8_t) PSLSE_MEMORY_WRITE;
		buffer[1] = (uint8_t) cmd->buffer_read->size;
		addr = (uint64_t*) &(buffer[2]);
		*addr = htole64(cmd->buffer_read->addr);
		memcpy(&(buffer[10]), &(data[offset]), cmd->buffer_read->size);
		cmd->buffer_read->abort = &(client->abort);
		if (put_bytes(client->fd, cmd->buffer_read->size+10, buffer,
			      cmd->dbg_fp, cmd->dbg_id, client->context)<0) {
			client_drop(client, PSL_IDLE_CYCLES);
		}
		debug_cmd_client(cmd->dbg_fp, cmd->dbg_id,
				 cmd->buffer_read->tag,
				 cmd->buffer_read->context);
		cmd->buffer_read->state = MEM_REQUEST;
		client->mem_access = (void *) cmd->buffer_read;
		cmd->buffer_read = NULL;
		free(buffer);
	}

buffer_data_done:
	free(parity);
	free(data);
buffer_data_fail:
	pthread_mutex_unlock(&(cmd->lock));
	pthread_mutex_unlock(cmd->psl_lock);
}

// Handle data returning from client for memory read
static void _handle_mem_read(struct cmd *cmd, struct cmd_event *event, int fd,
			    pthread_mutex_t *lock)
{
	uint8_t data[MAX_LINE_CHARS];
	uint64_t offset = event->addr & ~CACHELINE_MASK;

	// Client is returning data from memory read
	pthread_mutex_lock(lock);
	if (get_bytes_silent(fd, event->size, data, cmd->parms->timeout,
			     event->abort) < 0) {
		event->resp = PSL_RESPONSE_DERROR;
		event->state = MEM_DONE;
		debug_cmd_update(cmd->dbg_fp, cmd->dbg_id, event->tag,
				 event->context, event->resp);
		pthread_mutex_unlock(lock);
		return;
	}
	pthread_mutex_unlock(lock);
	memcpy((void *) &(event->data[offset]), (void *) &data, event->size);
	generate_cl_parity(event->data, event->parity);
	event->state = MEM_RECEIVED;
}

// Decide what to do with a client memory acknowledgement
void handle_mem_return(struct cmd *cmd, struct cmd_event *event, int fd,
		       pthread_mutex_t *lock)
{
	if (event->type==CMD_READ)
		_handle_mem_read(cmd, event, fd, lock);
	else
		event->state = MEM_DONE;
	debug_cmd_return(cmd->dbg_fp, cmd->dbg_id, event->tag, event->context);
}

// Mark memory event as address error in preparation for response
void handle_aerror(struct cmd *cmd, struct cmd_event *event)
{
	event->resp = PSL_RESPONSE_AERROR;
	event->state = MEM_DONE;
	debug_cmd_update(cmd->dbg_fp, cmd->dbg_id, event->tag,
			 event->context, event->resp);
}

// Send a randomly selected pending response back to AFU
void handle_response(struct cmd *cmd)
{
	struct cmd_event **head;
	struct cmd_event *event;
	int rc;

	// Select a random pending response (or none)
	pthread_mutex_lock(cmd->psl_lock);
	head = &cmd->list;
	pthread_mutex_lock(&(cmd->lock));
	while (*head != NULL) {
		// Fast track error responses
		if (((*head)->resp == PSL_RESPONSE_PAGED) ||
		    ((*head)->resp == PSL_RESPONSE_NRES) ||
		    ((*head)->resp == PSL_RESPONSE_NLOCK) ||
		    ((*head)->resp == PSL_RESPONSE_FLUSHED)) {
			event = *head;
			goto drive_resp;
		}
		if (((*head)->state == MEM_DONE) &&
		    !allow_reorder(cmd->parms)) {
			break;
		}
		head = &((*head)->_next);
	}
	event = *head;
	if ((event == NULL) ||
	    ((event->type==CMD_WRITE) && !allow_resp(cmd->parms))) {
		pthread_mutex_unlock(&(cmd->lock));
		pthread_mutex_unlock(cmd->psl_lock);
		return;
	}

drive_resp:
	if (event == cmd->buffer_read) {
		fatal_msg("Driving response when buffer read still active");
		_print_event(event);
		assert(event != cmd->buffer_read);
	}
	// Send response, remove command from list and free memory
	if ((event->resp == PSL_RESPONSE_PAGED) ||
	    (event->resp == PSL_RESPONSE_AERROR) ||
	    (event->resp == PSL_RESPONSE_DERROR)) {
		if ((cmd->client!=NULL) && (cmd->client[event->context]!=NULL))
		{
			_set_flush(cmd, event);
		}
		_update_pending_resps(cmd, PSL_RESPONSE_FLUSHED);
	}
	rc = psl_response(cmd->afu_event, event->tag, event->resp, 1, 0, 0);
	if (rc == PSL_SUCCESS) {
		debug_cmd_response(cmd->dbg_fp, cmd->dbg_id, event->tag);
		if (event->restart &&(cmd->client!=NULL) &&
		    (cmd->client[event->context]!=NULL)) {
			_clear_flush(cmd, event);
		}
		*head = event->_next;
		cmd->cmd_time[event->tag]=0;
		free(event->data);
		free(event->parity);
		free(event);
		cmd->credits++;
	}
	pthread_mutex_unlock(cmd->psl_lock);
	pthread_mutex_unlock(&(cmd->lock));
}

int client_cmd(struct cmd *cmd, struct client *client)
{
	struct cmd_event *event = cmd->list;
	while (event != NULL) {
		if (event->context != client->context) {
			event = event->_next;
			continue;
		}
		if (client->valid > 0) {
			return 1;
		}
		pthread_mutex_lock(&(cmd->lock));
		if (event->state != MEM_DONE) {
			if ((event->type == CMD_READ) ||
			    (event->type == CMD_WRITE) ||
			    (event->type == CMD_TOUCH)) {
				event->resp = PSL_RESPONSE_AERROR;
			}
			event->state = MEM_DONE;
		}
		pthread_mutex_unlock(&(cmd->lock));
		event = event->_next;
	}
	return 0;
}
