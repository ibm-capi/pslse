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
 *  handle_response(), handle_buffer_write(), handle_buffer_data() and
 *  handle_touch().  The state field is used to track the progress of each
 *  event until is fully completed and removed from the list completely.
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
		     FILE *dbg_fp, uint8_t dbg_id)
{
	int i, j;
	struct cmd *cmd;

	cmd = (struct cmd*) calloc(1, sizeof(struct cmd));
	if (!cmd) {
		perror("malloc");
		exit(-1);
	}

	cmd->afu_event = afu_event;
	cmd->mmio = mmio;
	cmd->parms = parms;
	cmd->psl_state = state;
	cmd->credits = parms->credits;
	cmd->page_entries.page_filter = ~((uint64_t) PAGE_MASK);
	cmd->page_entries.entry_filter = 0;
	for (i=0; i < LOG2_ENTRIES; i++) {
		cmd->page_entries.entry_filter <<= 1;
		cmd->page_entries.entry_filter += 1;
	}
	cmd->page_entries.entry_filter <<= PAGE_ADDR_BITS;
	for (i=0; i < PAGE_ENTRIES; i++) {
		for (j=0; j < PAGE_WAYS; j++) {
			cmd->page_entries.valid[i][j] = 0;
		}
	}
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
	case MEM_TOUCH:
		printf("TOUCH");
		break;
	case MEM_TOUCHED:
		printf("TOUCHED");
		break;
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

	// Handle commands to disconnected client
	if ((cmd->client == NULL) || (cmd->client[context] == NULL) ||
	    (cmd->client[context]->state == CLIENT_DROPPED)) {
		event->client_state = CLIENT_DROPPED;
		event->resp = PSL_RESPONSE_FAILED;
		event->state = MEM_DONE;
	}
	else {
		event->client_state = cmd->client[context]->state;
	}

	head = &(cmd->list);
	while ((*head != NULL) && !allow_reorder(cmd->parms))
		head = &((*head)->_next);
	event->_next = *head;
	*head = event;
	debug_cmd_add(cmd->dbg_fp, cmd->dbg_id, tag, context, command);
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
	// in the function handle_touch()
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
		_update_pending_resps(cmd, PSL_RESPONSE_NLOCK);
		cmd->locked = 1;
		cmd->lock_addr = addr & CACHELINE_MASK;
		_add_touch(cmd, handle, tag, command, abort, addr, 0);
		break;
	// Memory Reads
	case PSL_COMMAND_READ_CL_LCK:
		_update_pending_resps(cmd, PSL_RESPONSE_NLOCK);
		_update_pending_resps(cmd, PSL_RESPONSE_NLOCK);
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

// See if a command was sent by AFU and process if so
void handle_cmd(struct cmd *cmd, uint32_t parity_enabled, uint32_t latency)
{
	struct cmd_event *event;
	uint64_t address, address_parity;
	uint32_t command, command_parity, tag, tag_parity, size, abort, handle;
	uint8_t parity, fail;
	int rc;

	if (cmd==NULL)
		return;

	// Check for command from AFU
	rc = psl_get_command(cmd->afu_event, &command, &command_parity, &tag,
			     &tag_parity, &address, &address_parity, &size,
			     &abort, &handle);

	// No command ready
	if (rc != PSL_SUCCESS)
		return;

	// Is AFU running?
	if (*(cmd->psl_state) != PSLSE_RUNNING) {
		warn_msg("Command without jrunning, tag=0x%02x", tag);
		return;
	}

	// Check parity
	fail = 0;
	if (parity_enabled) {
		parity = generate_parity(address, ODD_PARITY);
		if (parity != address_parity) {
			_cmd_parity_error("address", (uint64_t) address,
					  address_parity);
			fail = 1;
		}
		parity = generate_parity(tag, ODD_PARITY);
		if (parity != tag_parity) {
			_cmd_parity_error("tag", (uint64_t) tag, tag_parity);
			fail = 1;
		}
		parity = generate_parity(command, ODD_PARITY);
		if (parity != command_parity) {
			_cmd_parity_error("code", (uint64_t) command,
					  command_parity);
			fail = 1;
		}
	}

	// Add failed command
	if (fail) {
		_add_other(cmd, handle, tag, command, abort,
			   PSL_RESPONSE_FAILED, 0);
		return;
	}

	// Check credits and parse
	if (!cmd->credits) {
		warn_msg("AFU issued command without any credits");
		_add_other(cmd, handle, tag, command, abort,
			   PSL_RESPONSE_FAILED, 0);
		return;
	}

	cmd->credits--;

	// No clients connected
	if ((cmd->client==NULL) || (cmd->client[handle] == NULL)) {
		_add_other(cmd, handle, tag, command, abort,
			   PSL_RESPONSE_FAILED, 0);
		return;
	}

	// Client is flushing new commands
	if (cmd->client[handle]->flushing && (command!=PSL_COMMAND_RESTART)) {
		_add_other(cmd, handle, tag, command, abort,
			   PSL_RESPONSE_FLUSHED, 0);
		return;
	}

	// Check for duplicate tag
	event = cmd->list;
	while (event!=NULL) {
		if (event->tag == tag) {
			error_msg("Duplicate tag 0x%02x", tag);
			return;
		}
		event = event->_next;
	}

	// Parse command
	_parse_cmd(cmd, command, tag, address, size, abort, handle, latency);
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

	// Make sure cmd structure is valid
	if ((cmd==NULL) || (cmd->client == NULL))
		return;

	// Randomly select a pending read (or none)
	while (event != NULL) {
		if ((event->type == CMD_READ) &&
		    (event->state != MEM_DONE) &&
		    !allow_reorder(cmd->parms)) {
			break;
		}
		event = event->_next;
	}

	// No valid event found
	if (event == NULL)
		return;

	// Abort if client disconnected
	client = cmd->client[event->context];
	if ((client == NULL) && (event->state != MEM_RECEIVED)) {
		event->resp = PSL_RESPONSE_FAILED;
		event->state = MEM_DONE;
		debug_cmd_update(cmd->dbg_fp, cmd->dbg_id, event->tag,
				 event->context, event->resp);
		return;
	}

	// After the client returns data with a call to the function
	// _handle_mem_read() issue buffer write with valid data and
	// prepare for response.
	if (event->state == MEM_RECEIVED) {
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
	}

	if (event->state != MEM_IDLE)
		return;

	if (!event->buffer_activity && allow_buffer(cmd->parms)) {
		// Buffer write with bogus data, but only once
		debug_cmd_buffer_write(cmd->dbg_fp, cmd->dbg_id, event->tag);
		psl_buffer_write(cmd->afu_event, event->tag, event->addr,
				 CACHELINE_BYTES, event->data, event->parity);
		event->buffer_activity = 1;
	}
	else if (client->mem_access == NULL) {
		// Send read request to client, set client->mem_access
		// to point to this event blocking any other memory
		// accesses to client until data is returned by call
		// to the _handle_mem_read() function.
		buffer[0] = (uint8_t) PSLSE_MEMORY_READ;
		buffer[1] = (uint8_t) event->size;
		addr = (uint64_t*) &(buffer[2]);
		*addr = htole64(event->addr);
		event->abort = &(client->abort);
		if (put_bytes(client->fd, 10, buffer, cmd->dbg_fp,
			      cmd->dbg_id, event->context)<0) {
			client_drop(client, PSL_IDLE_CYCLES, CLIENT_DROPPED);
		}
		event->state = MEM_REQUEST;
		debug_cmd_client(cmd->dbg_fp, cmd->dbg_id, event->tag,
				 event->context);
		client->mem_access = (void *) event;
	}
}

// Handle randomly selected pending write
void handle_buffer_read(struct cmd *cmd)
{
	struct cmd_event *event = cmd->list;
	struct client *client;

	// Check that cmd struct is valid buffer read is available
	if ((cmd==NULL) || (cmd->client==NULL) || (cmd->buffer_read!=NULL))
		return;

	// Randomly select a pending write (or none)
	while (event != NULL) {
		if ((event->type == CMD_WRITE) &&
		    (event->state == MEM_TOUCHED) &&
		    !allow_reorder(cmd->parms)) {
			break;
		}
		event = event->_next;
	}

	// No valid event found
	if (event == NULL)
		return;

	// Abort if client disconnected
	if ((cmd == NULL) || (cmd->client==NULL)) {
		event->resp = PSL_RESPONSE_FAILED;
		event->state = MEM_DONE;
		debug_cmd_update(cmd->dbg_fp, cmd->dbg_id, event->tag,
				 event->context, event->resp);
		return;
	}

	// Abort if client disconnected
	client = cmd->client[event->context];
	if (client == NULL) {
		event->resp = PSL_RESPONSE_FAILED;
		event->state = MEM_DONE;
		debug_cmd_update(cmd->dbg_fp, cmd->dbg_id, event->tag,
				 event->context, event->resp);
		return;
	}

	// Send buffer read request to AFU.  Setting cmd->buffer_read
	// will block any more buffer read requests until buffer read
	// data is returned and handled in handle_buffer_data().
	if (psl_buffer_read(cmd->afu_event, event->tag, event->addr,
			    CACHELINE_BYTES) == PSL_SUCCESS) {
		cmd->buffer_read = event;
		debug_cmd_buffer_read(cmd->dbg_fp, cmd->dbg_id, event->tag);
		event->state = MEM_BUFFER;
	}
}

// Handle randomly selected memory touch
void handle_touch(struct cmd *cmd)
{
	struct cmd_event *event = cmd->list;
	struct client *client;
	uint8_t buffer[10];
	uint64_t *addr;

	// Make sure cmd structure is valid
	if ((cmd == NULL) || (cmd->client==NULL))
		return;

	// Randomly select a pending touch (or none)
	while (event != NULL) {
		if (((event->type==CMD_TOUCH) || (event->type==CMD_WRITE)) &&
		     (event->state==MEM_IDLE) && !allow_reorder(cmd->parms)) {
			break;
		}
		event = event->_next;
	}

	// No valid event found
	if (event == NULL)
		return;

	// Abort if client disconnected
	if ((cmd == NULL) || (cmd->client==NULL)) {
		event->resp = PSL_RESPONSE_FAILED;
		event->state = MEM_DONE;
		debug_cmd_update(cmd->dbg_fp, cmd->dbg_id, event->tag,
				 event->context, event->resp);
		return;
	}

	// Abort if client disconnected
	client = cmd->client[event->context];
	if (client == NULL) {
		event->resp = PSL_RESPONSE_FAILED;
		event->state = MEM_DONE;
		debug_cmd_update(cmd->dbg_fp, cmd->dbg_id, event->tag,
				 event->context, event->resp);
		return;
	}

	// Check that memory request can be driven to client
	if(client->mem_access != NULL)
		return;

	// Send memory touch request to client
	buffer[0] = (uint8_t) PSLSE_MEMORY_TOUCH;
	buffer[1] = (uint8_t) event->size;
	addr = (uint64_t*) &(buffer[2]);
	*addr = htole64(event->addr & CACHELINE_MASK);
	event->abort = &(client->abort);
	if (put_bytes(client->fd, 10, buffer, cmd->dbg_fp, cmd->dbg_id,
		      event->context)<0) {
		client_drop(client, PSL_IDLE_CYCLES, CLIENT_DROPPED);
	}
	event->state = MEM_TOUCH;
	client->mem_access = (void *) event;
	debug_cmd_client(cmd->dbg_fp, cmd->dbg_id, event->tag, event->context);
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
	while (*head != NULL) {
		if ((*head)->type == CMD_INTERRUPT)
			break;
		head = &((*head)->_next);
	}
	event = *head;

	if (event == NULL)
		return;

	// Abort if client disconnected
	client = cmd->client[event->context];
	if (client == NULL) {
		event->resp = PSL_RESPONSE_FAILED;
		event->state = MEM_DONE;
		debug_cmd_update(cmd->dbg_fp, cmd->dbg_id, event->tag,
				 event->context, event->resp);
		return;
	}

	// Send interrupt to client
	buffer[0] = PSLSE_INTERRUPT;
	irq = htole16(cmd->irq);
	memcpy(&(buffer[1]), &irq, 2);
	event->abort = &(client->abort);
	if (put_bytes(client->fd, 3, buffer, cmd->dbg_fp, cmd->dbg_id,
		      event->context)<0) {
		client_drop(client, PSL_IDLE_CYCLES, CLIENT_DROPPED);
	}
	debug_cmd_client(cmd->dbg_fp, cmd->dbg_id, event->tag, event->context);
	event->state = MEM_DONE;
}

void handle_buffer_data(struct cmd *cmd, uint32_t parity_enable)
{
	uint8_t *parity_check;
	int rc;
	struct cmd_event *event;

	// Has struct been initialized?
	if ((cmd == NULL) || (cmd->buffer_read == NULL))
		return;

	// Check if buffer read data has returned from AFU
	event = cmd->buffer_read;
	rc = psl_get_buffer_read_data(cmd->afu_event, event->data,
				      event->parity);
	if (rc == PSL_SUCCESS) {
		if (parity_enable) {
			parity_check = (uint8_t*)malloc(DWORDS_PER_CACHELINE/8);
			generate_cl_parity(event->data, parity_check);
			if (strncmp((char *) event->parity,
				    (char *) parity_check,
				    DWORDS_PER_CACHELINE/8)) {
				error_msg("Buffer read parity error tag=0x%02x",
					  event->tag);
			}
			free(parity_check);
		}

		// Free buffer interface for another event
		cmd->buffer_read = NULL;

		// Randomly decide to not send data to client yet
		if (!event->buffer_activity && allow_buffer(cmd->parms)) {
			event->state = MEM_TOUCHED;
			event->buffer_activity = 1;
			return;
		}

		event->state = MEM_RECEIVED;
	}

}

void handle_mem_write(struct cmd *cmd)
{
	struct cmd_event **head = &cmd->list;
	struct cmd_event *event;
	struct client *client;
	uint64_t *addr;
	uint8_t *buffer;
	uint64_t offset;

	// Make sure cmd structure is valid
	if ((cmd == NULL) || (cmd->client==NULL))
		return;

	// Send any ready write data to client immediately
	while (*head != NULL) {
		if (((*head)->type == CMD_WRITE) &&
		    ((*head)->state == MEM_RECEIVED))
			break;
		head = &((*head)->_next);
	}
	event = *head;

	// Check if there is pending buffer read request
	if ((event == NULL) || (cmd->client == NULL))
		return;

	// Abort if client disconnected
	client = cmd->client[event->context];
	if (client == NULL) {
		event->resp = PSL_RESPONSE_FAILED;
		event->state = MEM_DONE;
		debug_cmd_update(cmd->dbg_fp, cmd->dbg_id, event->tag,
				 event->context, event->resp);
		return;
	}

	// Check that memory request can be driven to client
	if (client->mem_access != NULL)
		return;

	// Send data to client and clear event to allow
	// the next buffer read to occur.  The request will now await
	// confirmation from the client that the memory write was
	// successful before generating a response.  The client
	// response will cause a call to either handle_aerror() or
	// handle_mem_return().
	buffer = (uint8_t*)malloc(event->size+10);
	offset = event->addr & ~CACHELINE_MASK;
	buffer[0] = (uint8_t) PSLSE_MEMORY_WRITE;
	buffer[1] = (uint8_t) event->size;
	addr = (uint64_t*) &(buffer[2]);
	*addr = htole64(event->addr);
	memcpy(&(buffer[10]), &(event->data[offset]), event->size);
	event->abort = &(client->abort);
	if (put_bytes(client->fd, event->size+10, buffer, cmd->dbg_fp,
		      cmd->dbg_id, client->context)<0) {
		client_drop(client, PSL_IDLE_CYCLES, CLIENT_DROPPED);
	}
	debug_cmd_client(cmd->dbg_fp, cmd->dbg_id, event->tag,
			 event->context);
	event->state = MEM_REQUEST;
	client->mem_access = (void *) event;
}

// Handle data returning from client for memory read
static void _handle_mem_read(struct cmd *cmd, struct cmd_event *event, int fd)
{
	uint8_t data[MAX_LINE_CHARS];
	uint64_t offset = event->addr & ~CACHELINE_MASK;

	// Client is returning data from memory read
	if (get_bytes_silent(fd, event->size, data, cmd->parms->timeout,
			     event->abort) < 0) {
		event->resp = PSL_RESPONSE_DERROR;
		event->state = MEM_DONE;
		debug_cmd_update(cmd->dbg_fp, cmd->dbg_id, event->tag,
				 event->context, event->resp);
		return;
	}
	memcpy((void *) &(event->data[offset]), (void *) &data, event->size);
	generate_cl_parity(event->data, event->parity);
	event->state = MEM_RECEIVED;
}

// Calculate page address in cached index for translation
static void _calc_index(struct cmd *cmd, uint64_t *addr, uint64_t *index)
{
	*addr &= cmd->page_entries.page_filter;
	*index = *addr & cmd->page_entries.entry_filter;
	*index >>= PAGE_ADDR_BITS;
}

// Update age of translation entries and create new entry if needed
static void _update_age(struct cmd *cmd, uint64_t addr)
{
	uint64_t index;
	int i, set, age, oldest, empty;

	_calc_index(cmd, &addr, &index);
	set = age = oldest = 0;
	empty = PAGE_WAYS;
	for (i=0; i<PAGE_WAYS; i++) {
		if (cmd->page_entries.valid[index][i] &&
		    (cmd->page_entries.entry[index][i]!=addr)) {
			cmd->page_entries.age[index][i]++;
			if (cmd->page_entries.age[index][i] > age) {
				age = cmd->page_entries.age[index][i];
				oldest = i;
			}
		}
		if (!cmd->page_entries.valid[index][i] &&
		    (empty==PAGE_WAYS)) {
			empty = i;
		}
		if (cmd->page_entries.valid[index][i] &&
		    (cmd->page_entries.entry[index][i]==addr)) {
			cmd->page_entries.age[index][i] = 0;
			set = 1;
		}
	}

	// Entry found and updated
	if (set)
		return;

	// Empty slot exists
	if (empty<PAGE_WAYS) {
		cmd->page_entries.entry[index][empty] = addr;
		cmd->page_entries.valid[index][empty] = 1;
		cmd->page_entries.age[index][empty] = 0;
		return;
	}

	// Evict oldest entry and replace with new entry
	cmd->page_entries.entry[index][oldest] = addr;
	cmd->page_entries.valid[index][oldest] = 1;
	cmd->page_entries.age[index][oldest] = 0;
}

// Determine if page translation is already cached
static int _page_cached(struct cmd *cmd, uint64_t addr)
{
	uint64_t index;
	int i, hit;

	_calc_index(cmd, &addr, &index);
	i = hit = 0;
	while ((i<PAGE_WAYS) && cmd->page_entries.valid[index][i] &&
	       (cmd->page_entries.entry[index][i]!=addr)) {
		i++;
	}

	// Hit entry
	if ((i<PAGE_WAYS) && cmd->page_entries.valid[index][i])
		hit = 1;

	return hit;
}

// Decide what to do with a client memory acknowledgement
void handle_mem_return(struct cmd *cmd, struct cmd_event *event, int fd)
{
	struct client *client;

	// Abort if client disconnected
	client = cmd->client[event->context];
	if (client == NULL) {
		event->resp = PSL_RESPONSE_FAILED;
		event->state = MEM_DONE;
		debug_cmd_update(cmd->dbg_fp, cmd->dbg_id, event->tag,
				 event->context, event->resp);
		return;
	}

	// Randomly cause paged response
	if (((event->type!=CMD_WRITE) || (event->state!=MEM_REQUEST)) &&
	    !client->flushing && !_page_cached(cmd, event->addr) &&
	    allow_paged(cmd->parms)) {
		event->resp = PSL_RESPONSE_PAGED;
		event->state = MEM_DONE;
		debug_cmd_update(cmd->dbg_fp, cmd->dbg_id, event->tag,
				 event->context, event->resp);
		return;
	}

	_update_age(cmd, event->addr);

	if (event->type==CMD_READ)
		_handle_mem_read(cmd, event, fd);
	else if (event->type==CMD_TOUCH)
		event->state = MEM_DONE;
	else if (event->state==MEM_TOUCH)	// Touch before write
		event->state = MEM_TOUCHED;
	else					// Write after touch
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
	struct client *client;
	int rc;

	// Select a random pending response (or none)
	head = &cmd->list;
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
		return;
	}

drive_resp:
	if (event == cmd->buffer_read) {
		fatal_msg("Driving response when buffer read still active");
		_print_event(event);
		assert(event != cmd->buffer_read);
	}
	// Abort if client disconnected
	if ((cmd == NULL) || (cmd->client==NULL)) {
		event->resp = PSL_RESPONSE_FAILED;
		event->state = MEM_DONE;
		return;
	}

	// Check for valid client connected
	client = cmd->client[event->context];
	if (client == NULL) {
		event->resp = PSL_RESPONSE_FAILED;
		event->state = MEM_DONE;
		debug_cmd_update(cmd->dbg_fp, cmd->dbg_id, event->tag,
				 event->context, event->resp);
		return;
	}

	// Send response, remove command from list and free memory
	if ((event->resp == PSL_RESPONSE_PAGED) ||
	    (event->resp == PSL_RESPONSE_AERROR) ||
	    (event->resp == PSL_RESPONSE_DERROR)) {
		client->flushing = 1;
		_update_pending_resps(cmd, PSL_RESPONSE_FLUSHED);
	}
	rc = psl_response(cmd->afu_event, event->tag, event->resp, 1, 0, 0);
	if (rc == PSL_SUCCESS) {
		debug_cmd_response(cmd->dbg_fp, cmd->dbg_id, event->tag);
		if (event->restart)
			client->flushing = 0;
		*head = event->_next;
		free(event->data);
		free(event->parity);
		free(event);
		cmd->credits++;
	}
}

int client_cmd(struct cmd *cmd, struct client *client)
{
	int rc = 0;
	struct cmd_event *event = cmd->list;

	while (event != NULL) {
		if ((event->context != client->context) ||
		    (event->client_state == CLIENT_FREE)) {
			event = event->_next;
			continue;
		}
		if (client->state == CLIENT_VALID) {
			return 1;
		}
		rc = 1;
		if ((client->state == CLIENT_DROPPED) &&
		    (event->state != MEM_DONE)) {
			event->state = MEM_DONE;
			if ((event->type == CMD_READ) ||
			    (event->type == CMD_WRITE) ||
			    (event->type == CMD_TOUCH)) {
				event->resp = PSL_RESPONSE_FAILED;
			}
		}
		event = event->_next;
	}
	return rc;
}
