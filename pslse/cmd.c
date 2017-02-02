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
#include <inttypes.h>
#include <stdlib.h>
#include <sys/types.h>

#include "cmd.h"
#include "mmio.h"
#include "../common/debug.h"
#include "../common/utils.h"

#define IRQ_MASK       0x00000000000007FFL
#define CACHELINE_MASK 0xFFFFFFFFFFFFFF80L

// Initialize cmd structure for tracking AFU command activity
struct cmd *cmd_init(struct AFU_EVENT *afu_event, struct parms *parms,
		     struct mmio *mmio, volatile enum pslse_state *state,
		     char *afu_name, FILE * dbg_fp, uint8_t dbg_id)
{
	int i, j;
	struct cmd *cmd;

	cmd = (struct cmd *)calloc(1, sizeof(struct cmd));
	if (!cmd) {
		perror("malloc");
		exit(-1);
	}

	cmd->afu_event = afu_event;
	cmd->mmio = mmio;
	cmd->parms = parms;
	cmd->psl_state = state;
	cmd->credits = parms->credits;
#if defined PSL9 || defined PSL9lite
	cmd->pagesize = parms->pagesize;
#endif
	cmd->page_entries.page_filter = ~((uint64_t) PAGE_MASK);
	cmd->page_entries.entry_filter = 0;
	for (i = 0; i < LOG2_ENTRIES; i++) {
		cmd->page_entries.entry_filter <<= 1;
		cmd->page_entries.entry_filter += 1;
	}
	cmd->page_entries.entry_filter <<= PAGE_ADDR_BITS;
	for (i = 0; i < PAGE_ENTRIES; i++) {
		for (j = 0; j < PAGE_WAYS; j++) {
			cmd->page_entries.valid[i][j] = 0;
		}
	}
	cmd->afu_name = afu_name;
	cmd->dbg_fp = dbg_fp;
	cmd->dbg_id = dbg_id;
        
#if defined PSL9 
	cmd->afu_event->dma0_dvalid = 0;
#endif /* #ifdef PSL9 */
	return cmd;
}

static void _print_event(struct cmd_event *event)
{
	printf("Command event: client=");
	switch (event->state) {
	case CLIENT_VALID:
		printf("VALID ");
		break;
	default:
		printf("NONE ");
	}
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
	printf(" addr=0x%016" PRIx64 "\n\t", event->addr);
	printf(" size=0x%x", event->size);
	printf(" state=");
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
	       event->unlock, (event->command == PSL_COMMAND_RESTART));
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

static struct client *_get_client(struct cmd *cmd, struct cmd_event *event)
{
	// Make sure cmd and client are still valid
	if ((cmd == NULL) || (cmd->client == NULL) ||
	    (event->context >= cmd->max_clients))
		return NULL;

	// Abort if client disconnected
	if (cmd->client[event->context] == NULL) {
		event->resp = PSL_RESPONSE_FAILED;
		event->state = MEM_DONE;
		debug_cmd_update(cmd->dbg_fp, cmd->dbg_id, event->tag,
				 event->context, event->resp);
	}
	return cmd->client[event->context];
}

// Add new command to list
static void _add_cmd(struct cmd *cmd, uint32_t context, uint32_t tag,
		     uint32_t command, uint32_t abort, enum cmd_type type,
		     uint64_t addr, uint32_t size, enum mem_state state,
		     uint32_t resp, uint8_t unlock)
{
	struct cmd_event **head;
	struct cmd_event *event;

	if (cmd == NULL)
		return;
	event = (struct cmd_event *)calloc(1, sizeof(struct cmd_event));
	event->context = context;
	event->command = command;
	event->tag = tag;
	event->abt = abort;
	event->type = type;
	event->addr = addr;
	event->size = size;
	event->state = state;
	event->resp = resp;
#if defined PSL9 || PSL9lite
	// Temporary hack for now, as we don't touch/look @ PSL_SPAP reg 
	if (event->resp == PSL_RESPONSE_CONTEXT)
		event->resp_extra = 1;
	else
		event->resp_extra = 0;
#endif
	event->unlock = unlock;
#ifdef PSL9
	// make sure data buffer is big enough to hold 512B (MAX DMA xfer)
	event->data = (uint8_t *) malloc(CACHELINE_BYTES * 4);
	memset(event->data, 0xFF, CACHELINE_BYTES * 4);
	event->cpl_xfers_to_go = 0;  //init this to 0 (used for DMA read multi completion flow)
#else
	event->data = (uint8_t *) malloc(CACHELINE_BYTES);
	memset(event->data, 0xFF, CACHELINE_BYTES);
#endif /* ifdef PSL9 */
	event->parity = (uint8_t *) malloc(DWORDS_PER_CACHELINE / 8);
	memset(event->parity, 0xFF, DWORDS_PER_CACHELINE / 8);

	// Test for client disconnect
	if (_get_client(cmd, event) == NULL) {
		event->resp = PSL_RESPONSE_FAILED;
		event->state = MEM_DONE;
	}

	head = &(cmd->list);
	while ((*head != NULL) && !allow_reorder(cmd->parms))
		head = &((*head)->_next);
	event->_next = *head;
	*head = event;
	debug_msg("_add_cmd:created cmd_event @ 0x%016"PRIx64":command=0x%02x, type=0x%02x, tag=0x%02x, state=0x%03x", event, event->command, event->type, event->tag, event-> state );
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
		 MEM_IDLE, resp, 0);
}

// Format and add misc. command to list
static void _add_other(struct cmd *cmd, uint32_t handle, uint32_t tag,
		       uint32_t command, uint32_t abort, uint32_t resp)
{
	_add_cmd(cmd, handle, tag, command, abort, CMD_OTHER, 0, 0, MEM_DONE,
		 resp, 0);
}

// Check address alignment
static int _aligned(uint64_t addr, uint32_t size)
{
	// Check valid size
	if ((size == 0) || (size & (size - 1))) {
		warn_msg("AFU issued command with invalid size %d", size);
		return 0;
	}
	// Check aligned address
	if (addr & (size - 1)) {
		warn_msg("AFU issued command with unaligned address %016"
			 PRIx64, addr);
		return 0;
	}

	return 1;
}


#ifdef PSL9
// Format and add new p9 commands to list

static void _add_caia2(struct cmd *cmd, uint32_t handle, uint32_t tag,
		       uint32_t command, uint32_t abort, uint64_t addr)
{
	uint32_t resp = PSL_RESPONSE_DONE;
	enum cmd_type type = CMD_CAIA2;
	enum mem_state state = MEM_DONE;

	switch (command) {
		case PSL_COMMAND_CAS_E_4B:
		case PSL_COMMAND_CAS_NE_4B:
		case PSL_COMMAND_CAS_U_4B:
			//printf("in _add_caia2 for cmd_CAS 4B, address is 0x%016"PRIX64 "\n", addr);
			// Check command size and address
			if (!_aligned(addr, 16)) {
				_add_other(cmd, handle, tag, command, abort,
			  	 PSL_RESPONSE_FAILED);
			return;
			}
			type = CMD_CAS_4B;
			state = MEM_IDLE;
			break;
		case PSL_COMMAND_CAS_E_8B:
		case PSL_COMMAND_CAS_NE_8B:
		case PSL_COMMAND_CAS_U_8B:
			//printf("in _add_caia2 for cmd_CAS 8B, address is 0x%016"PRIX64 "\n", addr);
			// Check command size and address
			if (!_aligned(addr,16)) {
			_add_other(cmd, handle, tag, command, abort,
			   	PSL_RESPONSE_FAILED);
			return;
			}
			type = CMD_CAS_8B;
			state = MEM_IDLE;
			break;
		case PSL_COMMAND_XLAT_RD_P0:
			type = CMD_XLAT_RD;
			state = DMA_ITAG_REQ;
			break;
		case PSL_COMMAND_XLAT_WR_P0:
			type = CMD_XLAT_WR;
			state = DMA_ITAG_REQ;
			break;
		case PSL_COMMAND_XLAT_RD_TOUCH:
			type = CMD_XLAT_RD_TOUCH;
			//state = DMA_ITAG_REQ;
			state = MEM_IDLE;
			break;
		case PSL_COMMAND_XLAT_WR_TOUCH:
			type = CMD_XLAT_WR_TOUCH;
			//state = DMA_ITAG_REQ;
			state = MEM_IDLE;
			break;
		case PSL_COMMAND_ITAG_ABRT_RD:
			type = CMD_ITAG_ABRT_RD;
			state = DMA_ITAG_REQ;
			break;
		case PSL_COMMAND_ITAG_ABRT_WR:
			type = CMD_ITAG_ABRT_WR;
			state = DMA_ITAG_REQ;
			break;
		default:
			warn_msg("Unsupported command 0x%04x", cmd);
			break;

	}
	_add_cmd(cmd, handle, tag, command, abort, type, addr, 0, state,
		 resp, 0 );
}
#endif /* ifdef PSL9 */

// Format and add memory touch to command list
static void _add_touch(struct cmd *cmd, uint32_t handle, uint32_t tag,
		       uint32_t command, uint32_t abort, uint64_t addr,
		       uint32_t size, uint8_t unlock)
{
	// Check command size and address
	if (!_aligned(addr, size)) {
		_add_other(cmd, handle, tag, command, abort,
			   PSL_RESPONSE_FAILED);
		return;
	}
	_add_cmd(cmd, handle, tag, command, abort, CMD_TOUCH, addr,
		 CACHELINE_BYTES, MEM_IDLE, PSL_RESPONSE_DONE, unlock);
}

// Format and add unlock to command list
static void _add_unlock(struct cmd *cmd, uint32_t handle, uint32_t tag,
			uint32_t command, uint32_t abort)
{
	_add_cmd(cmd, handle, tag, command, abort, CMD_OTHER, 0, 0, MEM_DONE,
		 PSL_RESPONSE_DONE, 0);
}

// format a read_pe command and add it to the command list
static void _add_read_pe(struct cmd *cmd, uint32_t handle, uint32_t tag,
		      uint32_t command, uint32_t abort, uint64_t addr,
		      uint32_t size)
{
        // ultimately, this generates a return on the write buffer interface of the cacheline representing the pe
        // pe struct is basically all 0 except for WED
        // what parms does read_pe really need?
        // maybe only the handle and the tag
        // Check command size and address - not used in read_pe
	// if (!_aligned(addr, size)) {
	// 	_add_other(cmd, handle, tag, command, abort,
	//		   PSL_RESPONSE_FAILED);
	//	return;
	// }
	// Reads will be added to the list and will next be processed
	// in the function handle_buffer_write()
	// should this just call handle_buffer_write_pe???
        //printf( "in _add_read_pe \n" );
	_add_cmd(cmd, handle, tag, command, abort, CMD_READ_PE, addr, size,
		 MEM_IDLE, PSL_RESPONSE_DONE, 0);
}

// Format and add memory read to command list
static void _add_read(struct cmd *cmd, uint32_t handle, uint32_t tag,
		      uint32_t command, uint32_t abort, uint64_t addr,
		      uint32_t size)
{
	// Check command size and address
	if (!_aligned(addr, size)) {
		_add_other(cmd, handle, tag, command, abort,
			   PSL_RESPONSE_FAILED);
		return;
	}
	// Reads will be added to the list and will next be processed
	// in the function handle_buffer_write()
	_add_cmd(cmd, handle, tag, command, abort, CMD_READ, addr, size,
		 MEM_IDLE, PSL_RESPONSE_DONE, 0);
}

// Format and add memory write to command list
static void _add_write(struct cmd *cmd, uint32_t handle, uint32_t tag,
		       uint32_t command, uint32_t abort, uint64_t addr,
		       uint32_t size, uint8_t unlock)
{
	// Check command size and address
	if (!_aligned(addr, size)) {
		_add_other(cmd, handle, tag, command, abort,
			   PSL_RESPONSE_FAILED);
		return;
	}
	// Writes will be added to the list and will next be processed
	// in the function handle_touch()
	_add_cmd(cmd, handle, tag, command, abort, CMD_WRITE, addr, size,
		 MEM_IDLE, PSL_RESPONSE_DONE, unlock);
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
			   PSL_RESPONSE_CONTEXT);
		return;
	}
	switch (command) {
		// Interrupt
	case PSL_COMMAND_INTREQ:
		_add_interrupt(cmd, handle, tag, command, abort, irq);
		break;
		// Restart
	case PSL_COMMAND_RESTART:
		_add_other(cmd, handle, tag, command, abort, PSL_RESPONSE_DONE);
		break;
		// Cacheline lock
	case PSL_COMMAND_LOCK:
		_update_pending_resps(cmd, PSL_RESPONSE_NLOCK);
		cmd->locked = 1;
		cmd->lock_addr = addr & CACHELINE_MASK;
		_add_touch(cmd, handle, tag, command, abort, addr, size, 0);
		break;
		// Memory Reads
	case PSL_COMMAND_READ_CL_LCK:
		_update_pending_resps(cmd, PSL_RESPONSE_NLOCK);
		_update_pending_resps(cmd, PSL_RESPONSE_NLOCK);
		cmd->locked = 1;
		cmd->lock_addr = addr & CACHELINE_MASK;
	case PSL_COMMAND_READ_CL_RES:	/*fall through */
		if (!cmd->locked)
			cmd->res_addr = addr & CACHELINE_MASK;
	case PSL_COMMAND_READ_CL_NA:	/*fall through */
	case PSL_COMMAND_READ_CL_S:	/*fall through */
	case PSL_COMMAND_READ_CL_M:	/*fall through */
	case PSL_COMMAND_READ_PNA:	/*fall through */
		_add_read(cmd, handle, tag, command, abort, addr, size);
		break;
		// Cacheline unlock
	case PSL_COMMAND_UNLOCK:
		_add_unlock(cmd, handle, tag, command, abort);
		break;
		// Memory Writes
	case PSL_COMMAND_WRITE_UNLOCK:
		unlock = 1;
	case PSL_COMMAND_WRITE_C:	/*fall through */
		if (!unlock)
			cmd->res_addr = 0L;
	case PSL_COMMAND_WRITE_MI:	/*fall through */
	case PSL_COMMAND_WRITE_MS:	/*fall through */
	case PSL_COMMAND_WRITE_NA:	/*fall through */
	case PSL_COMMAND_WRITE_INJ:	/*fall through */
		if (!(latency % 2) || (latency > 3))
			error_msg("Write with invalid br_lat=%d", latency);
		_add_write(cmd, handle, tag, command, abort, addr, size,
			   unlock);
		break;
		// Treat these as memory touch to test for valid addresses
	case PSL_COMMAND_EVICT_I:
		if (cmd->locked && cmd->res_addr) {
			_add_other(cmd, handle, tag, command, abort,
				   PSL_RESPONSE_NRES);
			break;
		}
	case PSL_COMMAND_PUSH_I:	/*fall through */
	case PSL_COMMAND_PUSH_S:	/*fall through */
		if (cmd->locked) {
			_add_other(cmd, handle, tag, command, abort,
				   PSL_RESPONSE_NLOCK);
			break;
		}
	case PSL_COMMAND_TOUCH_I:
	case PSL_COMMAND_TOUCH_S:	/*fall through */
	case PSL_COMMAND_TOUCH_M:	/*fall through */
	case PSL_COMMAND_FLUSH:	/*fall through */
		_add_touch(cmd, handle, tag, command, abort, addr, size,
			   unlock);
		break;
	case PSL_COMMAND_READ_PE:	/*fall through */
		_add_read_pe(cmd, handle, tag, command, abort, addr, size);
		break;
#ifdef PSL9
	case PSL_COMMAND_CAS_E_4B:	
	case PSL_COMMAND_CAS_NE_4B:	
	case PSL_COMMAND_CAS_U_4B:	
	case PSL_COMMAND_CAS_E_8B:	
	case PSL_COMMAND_CAS_NE_8B:	
	case PSL_COMMAND_CAS_U_8B:	
	case PSL_COMMAND_XLAT_RD_P0:
	case PSL_COMMAND_XLAT_WR_P0:
	case PSL_COMMAND_XLAT_RD_TOUCH:
	case PSL_COMMAND_XLAT_WR_TOUCH:
	case PSL_COMMAND_ITAG_ABRT_RD:
	case PSL_COMMAND_ITAG_ABRT_WR:
		_add_caia2(cmd, handle, tag, command, abort,addr);
		break;
#endif /* ifdef PSL9 */
	default:
		warn_msg("Unsupported command 0x%04x", cmd);
		_add_other(cmd, handle, tag, command, abort,
			   PSL_RESPONSE_FAILED);
		break;
	}
}

// Report parity error on some command bus
static void _cmd_parity_error(const char *msg, uint64_t value, uint8_t parity)
{
	error_msg("Command %s parity error 0x%04" PRIx64 ",%d", msg, value,
		  parity);
}

// See if a command was sent by AFU and process if so
void handle_cmd(struct cmd *cmd, uint32_t parity_enabled, uint32_t latency)
{
	struct cmd_event *event;
	uint64_t address, address_parity;
#if defined PSL9 || defined PSL9lite
	uint32_t command, command_parity, tag, tag_parity, size, abort, handle, cpagesize;
#else
	uint32_t command, command_parity, tag, tag_parity, size, abort, handle;
#endif
	uint8_t parity, fail;
	int rc;

	if (cmd == NULL)
		return;

	// Check for command from AFU
	rc = psl_get_command(cmd->afu_event, &command, &command_parity, &tag,
			     &tag_parity, &address, &address_parity, &size,
#if defined PSL9 || defined PSL9lite
			     &abort, &handle, &cpagesize);
#else
			     &abort, &handle);
#endif

	// No command ready
	if (rc != PSL_SUCCESS)
		return;

	debug_msg
	    ("%s:COMMAND tag=0x%02x code=0x%04x size=0x%02x abt=%d cch=0x%04x",
	     cmd->afu_name, tag, command, size, abort, handle);
#ifdef PSL9
	debug_msg("%s:COMMAND tag=0x%02x addr=0x%016"PRIx64 " cpagesize= 0x%x ", cmd->afu_name,
 
		  tag, address, cpagesize);
#endif
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
			   PSL_RESPONSE_FAILED);
		return;
	}
	// Check credits and parse
	if (!cmd->credits) {
		warn_msg("AFU issued command without any credits");
		_add_other(cmd, handle, tag, command, abort,
			   PSL_RESPONSE_FAILED);
		return;
	}

	cmd->credits--;

	// Client not connected
	if ((cmd == NULL) || (cmd->client == NULL) ||
	    (handle >= cmd->max_clients) || ((cmd->client[handle]) == NULL)) {
		_add_other(cmd, handle, tag, command, abort,
			   PSL_RESPONSE_FAILED);
		return;
	}
	// Client is flushing new commands
	if ((cmd->client[handle]->flushing == FLUSH_FLUSHING) &&
	    (command != PSL_COMMAND_RESTART)) {
		_add_other(cmd, handle, tag, command, abort,
			   PSL_RESPONSE_FLUSHED);
		return;
	}
	// Check for duplicate tag
	event = cmd->list;
	while (event != NULL) {
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
	struct cmd_event *event;
	struct client *client;
	uint8_t buffer[10];
	uint64_t *addr;
	int quadrant, byte;

	// Make sure cmd structure is valid
	if (cmd == NULL)
		return;

	//printf( "handle_buffer_write \n" );
	// Randomly select a pending read or read_pe (or none)
	event = cmd->list;
	while (event != NULL) {
	        if (((event->type == CMD_READ) || (event->type == CMD_READ_PE) )&&
		    (event->state != MEM_DONE) &&
		    ((event->client_state != CLIENT_VALID) ||
		     !allow_reorder(cmd->parms))) {
			break;
		}
#if defined PSL9 || defined PSL9lite
	        if (((event->type == CMD_CAS_4B) || (event->type == CMD_CAS_8B) )&&
		    (event->state == MEM_CAS_RD) &&
		    ((event->client_state != CLIENT_VALID) ||
		     !allow_reorder(cmd->parms))) {
			break;
		}
#endif
		event = event->_next;
	}

	//printf( "handle_buffer_write: we've picked an event \n" );
	// Test for client disconnect
	if ((event == NULL) || ((client = _get_client(cmd, event)) == NULL))
		return;

	// After the client returns data with a call to the function
	// _handle_mem_read() issue buffer write with valid data and
	// prepare for response.
	// While a read_pe generates it's own data and doesn't go through the _handle_mem_read() routine,
	// a read_pe still needs to generate a call to psl_buffer_write 
	// OTHER REASONS to call are: CAS commands...they need to get back data via the buffer write port
	// but don't send the read data back, it's used for the operation
	if ((event->state == MEM_RECEIVED) && ((event->type == CMD_READ) || (event->type == CMD_READ_PE))) {
		if (psl_buffer_write(cmd->afu_event, event->tag, event->addr,
				     CACHELINE_BYTES, event->data,
				     event->parity) == PSL_SUCCESS) {
			debug_msg("%s:BUFFER WRITE tag=0x%02x", cmd->afu_name,
				  event->tag);
			for (quadrant = 0; quadrant < 4; quadrant++) {
				DPRINTF("DEBUG: Q%d 0x", quadrant);
				for (byte = 0; byte < CACHELINE_BYTES / 4;
				     byte++) {
					DPRINTF("%02x", event->data[byte]);
				}
				DPRINTF("\n");
			}
			event->resp = PSL_RESPONSE_DONE;
			event->state = MEM_DONE;
			debug_cmd_buffer_write(cmd->dbg_fp, cmd->dbg_id,
					       event->tag);
			debug_cmd_update(cmd->dbg_fp, cmd->dbg_id, event->tag,
					 event->context, event->resp);
		}
	}

#if defined PSL9 || defined PSL9lite

                if (event->state == MEM_CAS_RD) {
		  buffer[0] = (uint8_t) PSLSE_MEMORY_READ;
		  buffer[1] = (uint8_t) event->size;
		  addr = (uint64_t *) & (buffer[2]);
		  *addr = htonll(event->addr);
		  event->abort = &(client->abort);
		  debug_msg("%s:MEMORY READ FOR CAS tag=0x%02x size=%d addr=0x%016"PRIx64,
			    cmd->afu_name, event->tag, event->size, event->addr);
		  if (put_bytes(client->fd, 10, buffer, cmd->dbg_fp,
				cmd->dbg_id, event->context) < 0) {
		    client_drop(client, PSL_IDLE_CYCLES, CLIENT_NONE);
		  }
		  event->state = MEM_REQUEST;
		  client->mem_access = (void *)event;
		  return; //exit immediately
		}

#endif
	if (event->state != MEM_IDLE)
		return;

	if (!event->buffer_activity && allow_buffer(cmd->parms)) {
		// Buffer write with bogus data, but only once
	        // should I skip this in the case of read_pe?
		debug_cmd_buffer_write(cmd->dbg_fp, cmd->dbg_id, event->tag);
		psl_buffer_write(cmd->afu_event, event->tag, event->addr,
				 CACHELINE_BYTES, event->data, event->parity);
		event->buffer_activity = 1;
	} else if (client->mem_access == NULL) {
	        // if read:
		// Send read request to client, set client->mem_access
		// to point to this event blocking any other memory
		// accesses to client until data is returned by call
		// to the _handle_mem_read() function.
	        // if read_pe:
		// build data and parity to represent pe
	        // set event->state to mem_received
                if (event->type == CMD_READ) {
		  buffer[0] = (uint8_t) PSLSE_MEMORY_READ;
		  buffer[1] = (uint8_t) event->size;
		  addr = (uint64_t *) & (buffer[2]);
		  *addr = htonll(event->addr);
		  event->abort = &(client->abort);
		  debug_msg("%s:MEMORY READ tag=0x%02x size=%d addr=0x%016"PRIx64,
			    cmd->afu_name, event->tag, event->size, event->addr);
		  if (put_bytes(client->fd, 10, buffer, cmd->dbg_fp,
				cmd->dbg_id, event->context) < 0) {
		    client_drop(client, PSL_IDLE_CYCLES, CLIENT_NONE);
		  }
		  event->state = MEM_REQUEST;
		  debug_cmd_client(cmd->dbg_fp, cmd->dbg_id, event->tag,
				   event->context);
		  client->mem_access = (void *)event;
		}
                if (event->type == CMD_READ_PE) {
		  // init data
		  memset(event->data, 0x00, CACHELINE_BYTES);		  
		  // set wed portion
		  // event->data pointer to uint8
		  // client->wed uint64
		  // event->data[116:123] is wed portion
		  memcpy((void *)&(event->data[116]),(void *)&(client->wed), 8);
		  generate_cl_parity(event->data, event->parity);
		  event->state = MEM_RECEIVED;
		  debug_msg("%s:PROCESS ELEMENT READ tag=0x%02x handle=%d",
			    cmd->afu_name, event->tag, event->context);
		}
	}
}

// Handle randomly selected pending write
void handle_buffer_read(struct cmd *cmd)
{
	struct cmd_event *event;

	// Check that cmd struct is valid buffer read is available
	if ((cmd == NULL) || (cmd->buffer_read != NULL))
		return;

	// Randomly select a pending write (or none)
	event = cmd->list;
	while (event != NULL) {
		if ((event->type == CMD_WRITE) &&
		    (event->state == MEM_TOUCHED) &&
		    ((event->client_state != CLIENT_VALID) ||
		     !allow_reorder(cmd->parms))) {
			break;
		}
#if defined PSL9 || defined PSL9lite
		//Randomly select a pending CAS (or none)
		if (((event->type == CMD_CAS_4B) || (event->type == CMD_CAS_8B)) &&
		    (event->state == MEM_IDLE) &&
		    ((event->client_state != CLIENT_VALID) ||
		     !allow_reorder(cmd->parms))) {
			//printf("sending buffer read request for CAS smd \n");
			break;
		}
#endif
		event = event->_next;
	}

	// Test for client disconnect
	if ((event == NULL) || (_get_client(cmd, event) == NULL))
		return;

	// Send buffer read request to AFU.  Setting cmd->buffer_read
	// will block any more buffer read requests until buffer read
	// data is returned and handled in handle_buffer_data().
	debug_msg("%s:BUFFER READ tag=0x%02x addr=0x%016"PRIx64, cmd->afu_name,
		  event->tag, event->addr);
	if (psl_buffer_read(cmd->afu_event, event->tag, event->addr,
			    CACHELINE_BYTES) == PSL_SUCCESS) {
		cmd->buffer_read = event;
		debug_cmd_buffer_read(cmd->dbg_fp, cmd->dbg_id, event->tag);
		event->state = MEM_BUFFER;
	}
}

#ifdef PSL9
// Handle  pending dma0 write - check is done here to make sure that
// dma transaction stays within a 4k page. If not, simulation ends w/error.
// Transactions up to 512B are supported.
void handle_dma0_write(struct cmd *cmd)
{
	struct cmd_event **head;
	struct cmd_event *event;
	struct client *client;
	uint64_t *addr;
	uint8_t *buffer;
	
	// Check that cmd struct is valid 
	if (cmd == NULL) 
		return;

	// Send any ready write data to client immediately
	head = &cmd->list;
	while (*head != NULL) {
		if ((((*head)->type == CMD_DMA_WR) || ((*head)->type == CMD_DMA_WR_AMO)) &&
		    ((*head)->state == DMA_OP_REQ))
			break;
	if (((*head)->type == CMD_DMA_WR_AMO) && ((*head)->state == DMA_MEM_RESP))
 			goto amo_wb;

		head = &((*head)->_next);
	}
	event = *head;


	// Test for client disconnect or nothing to do....
	if ((event == NULL) || ((client = _get_client(cmd, event)) == NULL))
		return;
	// Check that memory request can be driven to client
	if (client->mem_access != NULL) {
		printf("client->mem_access NOT NULL!!!!! \n");
		return;
	}
	// check to make sure transaction will stay within a 4K boundary
	if ((event->addr+0x1000) <= (event->addr+(uint64_t)event->dsize))
		error_msg ("TRANSACTION CROSSES 4K BOUNDARY - WILL CAUSE PCI BUS ERROR!!!! boundary= 0x%016"PRIx64" last byte= 0x%016"PRIx64,
			 (event->addr+0x1000), (event->addr +event->dsize));
	else
		debug_msg ("TRANSACTION IS GOOD TO GO !!!! boundary= 0x%016"PRIx64" last byte= 0x%016"PRIx64,
			 (event->addr+0x1000), (event->addr +event->dsize));
	debug_msg("%s:DMA0 WRITE BUFFER itag=0x%02x addr=0x%016"PRIx64" port=0x%2x", cmd->afu_name,
		  event->itag, event->addr, client->fd);
	// Send data to client and clear event to allow
	// the next buffer read to occur.  The request will now await
	// confirmation from the client that the memory write was
	// successful before generating a response.  
	if (event->type == CMD_DMA_WR) {
		buffer = (uint8_t *) malloc(event->dsize + 11);
		buffer[0] = (uint8_t) PSLSE_DMA0_WR;
		buffer[1] = (uint8_t) ((event->dsize & 0x0F00) >>8);
		buffer[2] = (uint8_t) (event->dsize & 0xFF);
		addr = (uint64_t *) & (buffer[3]);
		*addr = htonll(event->addr);
		memcpy(&(buffer[11]), &(event->data[0]), event->dsize);
		event->abort = &(client->abort);
		debug_msg("%s:DMA0 MEMORY WRITE utag=0x%02x size=%d addr=0x%016"PRIx64" port=0x%2x",
		  	cmd->afu_name, event->utag, event->dsize, event->addr, client->fd);
		if (put_bytes(client->fd, event->dsize + 11, buffer, cmd->dbg_fp,
		      cmd->dbg_id, client->context) < 0) {
			client_drop(client, PSL_IDLE_CYCLES, CLIENT_NONE);
		}
	} else { // event->type == CMD_DMA_WR_AMO
		buffer = (uint8_t *) malloc(27);
		buffer[0] = (uint8_t) PSLSE_DMA0_WR_AMO;
		buffer[1] = (uint8_t) event->dsize;
		addr = (uint64_t *) & (buffer[2]);
		*addr = htonll(event->addr);
		buffer[10] = event->atomic_op;
		memcpy(&(buffer[11]), &(event->data[0]), 16);
		event->abort = &(client->abort);
		debug_msg("%s:DMA0 MEMORY WRITE for AMO utag=0x%02x size=%d addr=0x%016"PRIx64" port=0x%2x",
		  	cmd->afu_name, event->utag, event->dsize, event->addr, client->fd);
		if (put_bytes(client->fd, 27, buffer, cmd->dbg_fp,
		      cmd->dbg_id, client->context) < 0) {
			client_drop(client, PSL_IDLE_CYCLES, CLIENT_NONE);
		}
	}

	// create a separate function to do the sent utag status
	event->state = DMA_SEND_STS;
	client->mem_access = (void *)event;
	return;

amo_wb: event = *head;
debug_msg ("event->atomic_op = 0x%x ", event->atomic_op);
	if ((event->atomic_op & 0x3f) < 0x20) {
	//randomly decide not to return data yet
		if (!allow_resp(cmd->parms)) 
			return;
		
		event->cpl_type = 4; //always 4 for atomic completion response
		event->cpl_byte_count = event->dsize; // not valid for AMO but we do it anyway for debug
		event->cpl_laddr = (uint32_t) (event->cpl_laddr & 0x000000000000000C);
		debug_msg("%s:DMA0 AMO FETCH DATA WB  utag=0x%02x size=%d addr=0x%016"PRIx64 ,
		  	cmd->afu_name, event->utag, event->dsize, event->addr);

		if (psl_dma0_cpl_bus_write(cmd->afu_event, event->utag, event->dsize, event->cpl_type,
			event->dsize, event->cpl_laddr, event->cpl_byte_count,
			event->data) == PSL_SUCCESS) {
			debug_msg("%s:DMA0 CPL BUS WRITE utag=0x%02x", cmd->afu_name,
				  event->utag);
			event->resp = PSL_RESPONSE_DONE;
			//event->state = DMA_CPL_SENT;
			//see if this fixes the core dumps
			event->state = MEM_DONE;
			} else 
				printf ("looks like we didn't have success writing cpl data? \n");
		}
		return;

}


// Send UTAG SENT via DMA port back to AFU
void handle_dma0_sent_sts(struct cmd *cmd)
{
	struct cmd_event **head;
	struct cmd_event *event;
	struct client *client;
	
	// Check that cmd struct is valid 
	if (cmd == NULL) 
		return;

	// look for any pending sent_utag_sts to send to AFU 
	head = &cmd->list;
	while (*head != NULL) {
		if ((((*head)->type == CMD_DMA_WR) || ((*head)->type == CMD_DMA_WR_AMO)) &&
		    ((*head)->state == DMA_SEND_STS))
			break;
		head = &((*head)->_next);
	}
	event = *head;

	// Test for client disconnect or nothing to do....
	if ((event == NULL) || ((client = _get_client(cmd, event)) == NULL))
		return;

	event->sent_sts = 0x1;
	if (psl_dma0_sent_utag(cmd->afu_event, event->utag, event->sent_sts)
				      == PSL_SUCCESS) {
		debug_msg("%s:DMA0 SENT UTAG STS, state now DMA_MEM_RESP FOR DMA_WR utag=0x%02x",
			 cmd->afu_name, event->utag);
		//state goes to MEM_DONE when Memory ACK is received back from client
		event->state = DMA_MEM_RESP;

	} else
		debug_msg("%s:DMA0 SENT UTAG STS not SENT, still DMA_SEND_STS FOR DMA_WR utag=0x%02x",
		 cmd->afu_name, event->utag);
}

// Handle randomly selected pending DMA0 read, send request to client for real data
//  or do final write to AFU w/valid data after it is received from client.
void handle_dma0_read(struct cmd *cmd)
{
	struct cmd_event *event;
	struct client *client;
	uint8_t buffer[10];
	uint64_t *addr;
	int quadrant, byte;

	// Make sure cmd structure is valid
	if (cmd == NULL)
		return;


	// Randomly select a pending dma0 read (or none)
	event = cmd->list;
	while (event != NULL) {
	        if ((event->type == CMD_DMA_RD) &&
		    (event->state == DMA_CPL_PARTIAL) &&
		    ((event->client_state != CLIENT_VALID) ||
		     !allow_reorder(cmd->parms))) {
			break;
		}
	        if ((event->type == CMD_DMA_RD) &&
		    (event->state != DMA_CPL_SENT) &&
		    ((event->client_state != CLIENT_VALID) ||
		     !allow_reorder(cmd->parms))) {
			break;
		}
		event = event->_next;
	}

	// Test for client disconnect
	if ((event == NULL) || ((client = _get_client(cmd, event)) == NULL))
		return;

	// After the client returns data with a call to the function
	// _handle_mem_read() issue dma0 completion bus
	// write with valid data and
	// prepare for response.
	// TODO update to handle cpl_response from DMA_WR_AMO commands

	if ((event->state == DMA_CPL_PARTIAL) || (event->state == DMA_MEM_RESP)) {
        	//randomly decide not to return data yet only if this isn't a multi-cycle cpl in progress
		if ((event->state == DMA_MEM_RESP) && (!allow_resp(cmd->parms))) 
			return;
		
		if (event->cpl_xfers_to_go == 0) {
			if (event->state == DMA_MEM_RESP)  {  //start of transaction
				event->cpl_byte_count = event->dsize;
				event->cpl_laddr = (uint32_t) (event->addr & 0x00000000000003FF);
			}
			if (event->cpl_byte_count <= 128) { // Single cycle single completion flow
				event->cpl_type = 0; //always 0 for read up to 128bytes
				event->cpl_size = event->cpl_byte_count;
				//event->cpl_byte_count = event->dsize;
				//event->cpl_laddr = (uint32_t) (event->addr & 0x00000000000003FF);
				if (psl_dma0_cpl_bus_write(cmd->afu_event, event->utag, event->dsize, event->cpl_type,
					event->cpl_size, event->cpl_laddr, event->cpl_byte_count,
					event->data) == PSL_SUCCESS) {
				                debug_msg( "%s:DMA0 req <= 128 bytes: CPL BUS WRITE: cpl_size=0x%04x utag=0x%02x laddr = 0x%8x", 
							   cmd->afu_name, 
							   event->cpl_size,
							   event->utag,
							   event->cpl_laddr );
						int line = 0;
						for (quadrant = 0; quadrant < 4; quadrant++) {
							DPRINTF("DEBUG: Q%d 0x", quadrant);
							for (byte = line; byte < line+32; byte++) {
								DPRINTF("%02x", event->data[byte+event->cpl_laddr]);
							}
							DPRINTF("\n");
							line +=32;
						}
					event->resp = PSL_RESPONSE_DONE;
					event->state = DMA_CPL_SENT;
					event->cpl_xfers_to_go = 0; // Make sure this is cleared at end of xfer
				} 
			} else	if (event->cpl_byte_count <= 512) { //Multi cycle single completion flow
			                // need way to lock DMA bus so nothing else goes out over it until this transaction completes? TODO
			                // 128 < dsize <= 256 implies multi cycle single completion
			                // 256 < dsize <= 512 implies multi cycle multi completion
			                // there could be up to 4 passes through this code - need to track where we are in data and dsize
			                // maybe a cpl chunk pointer? or cpl bytes sent counter?

					event->cpl_xfers_to_go = 1; //will stay set to 1 until byte count= cpl_size 
					event->cpl_type = 0; //always 0 for first xfer of 128bytes
					if (event->cpl_byte_count < 256)
						event->cpl_size = event->cpl_byte_count;
					else
						event->cpl_size = 256;
					//event->cpl_byte_count = event->dsize;
					//event->cpl_laddr = (uint32_t) (event->addr & 0x00000000000003FF);
					if (psl_dma0_cpl_bus_write(cmd->afu_event, event->utag, event->dsize, event->cpl_type,
						event->cpl_size, event->cpl_laddr, event->cpl_byte_count,
						event->data) == PSL_SUCCESS) {
							debug_msg( "%s:DMA0 128 bytes < req <= 512 bytes: CPL BUS WRITE: cpl_size=0x%04x utag=0x%02x laddr= 0x%8x", cmd->afu_name, 
								   event->cpl_size,
								   event->utag ,
							           event->cpl_laddr );
							int line = 0;
							for (quadrant = 0; quadrant < 4; quadrant++) {
								DPRINTF("DEBUG: Q%d 0x", quadrant);
								for (byte = line; byte < line+32; byte++) {
									DPRINTF("%02x", event->data[byte]);
								}
								DPRINTF("\n");
								line +=32;
							}
					event->state = DMA_CPL_PARTIAL;
					}
			} else 
			        error_msg ("ERROR: REQ FOR DMA xfer > 512B we should not be here!!!");
		} else  {  //  second pass thru
				event->cpl_type = 1; //1 for last cycle, nothing valid but cpl_type, data and utag
				// psl_dma0_cpl_bus_write will make adjustments to correct cpl_size & laddr
				//event->cpl_size = event->dsize; <<<<---THIS IS NOT RIGHT
				event->cpl_byte_count = event->dsize;
				event->cpl_laddr = (uint32_t) (event->addr & 0x00000000000003FF);
				if (psl_dma0_cpl_bus_write(cmd->afu_event, event->utag, event->dsize, event->cpl_type,
					event->cpl_size, event->cpl_laddr, event->cpl_byte_count,
					event->data) == PSL_SUCCESS) {
						debug_msg( "%s:DMA0  128 bytes < req <= 512 bytes: CPL BUS WRITE B: size=0x%04x tag=0x%02x, laddr= 0x%8x", cmd->afu_name,
							   event->dsize,
							   event->utag ,
							   event->cpl_laddr );
						int line = 128;
						for (quadrant = 0; quadrant < 4; quadrant++) {
							DPRINTF("DEBUG: Q%d 0x", quadrant);
							for (byte = line; byte < line+32; byte++) {
								DPRINTF("%02x", event->data[byte]);
							}
							DPRINTF("\n");
							line +=32;
						}
				}
				if (event->cpl_byte_count == event->cpl_size) {  //this was last transfer
					event->resp = PSL_RESPONSE_DONE;
					event->state = DMA_CPL_SENT;
					event->cpl_xfers_to_go = 0; // Make sure to clear this at end of transfer
				// be sure to unlock the DMA bus after this gets loaded into afu_event struct TODO
					}
				else  { //dec byte count, inc addr for next transfer
					// event->cpl_xfers_to_go should still be 1 from original setting
					event->cpl_byte_count -= 256;
					if (event->cpl_byte_count <= 128)// last transfer will be single cycle	
						event->cpl_size = event->cpl_byte_count;
					event->cpl_laddr += 256;
					event->cpl_xfers_to_go = 0; // Make sure to clear this at end of transfer
					debug_msg("%s:DMA0 CPL BUS WRITE NEXT XFER cpl_size=0x%02x and cpl_laddr=%03x and cpl_byte_count=0x%03x", cmd->afu_name,
						event->cpl_byte_count, event->cpl_laddr, event->cpl_byte_count);
				}
		}
	}

	if (event->state != DMA_OP_REQ)
		return;

	if (client->mem_access == NULL) {
	        // if read:
		// Send read request to client, set client->mem_access
		// to point to this event blocking any other memory
		// accesses to client until data is returned by call
		// to the _handle_mem_read() function.
                if (event->type == CMD_DMA_RD) {
		  buffer[0] = (uint8_t) PSLSE_DMA0_RD;
		  buffer[1] = (uint8_t) ((event->dsize & 0x0F00) >>8);
		  buffer[2] = (uint8_t) (event->dsize & 0xFF);
		 // buffer[1] = (uint8_t) event->dsize;
		  addr = (uint64_t *) & (buffer[3]);
		  *addr = htonll(event->addr);
		  event->abort = &(client->abort);
		  debug_msg("%s:DMA0 MEMORY READ utag=0x%02x size=%d addr=0x%016"PRIx64" port = 0x%2x",
			    cmd->afu_name, event->utag, event->dsize, event->addr, client->fd);
		  if (put_bytes(client->fd, 11, buffer, cmd->dbg_fp,
				cmd->dbg_id, event->context) < 0) {
		    client_drop(client, PSL_IDLE_CYCLES, CLIENT_NONE);
		  }
		// Now need to send UTAG SENT via DMA port back to AFU
	if (psl_dma0_sent_utag(cmd->afu_event, event->utag, event->sent_sts)
				      == PSL_SUCCESS) {
			debug_msg("%s:DMA0 SENT UTAG STS, state now DMA_MEM_REQ FOR DMA_RD utag=0x%02x", cmd->afu_name,
				  event->utag);

		  event->state = DMA_MEM_REQ;
		 // debug_cmd_client(cmd->dbg_fp, cmd->dbg_id, event->tag,
		//		   event->context);
		  client->mem_access = (void *)event;
                    }
		}
 	}
}


#endif /* ifdef PSL9 */
// Handle randomly selected memory touch
void handle_touch(struct cmd *cmd)
{
	struct cmd_event *event;
	struct client *client;
	uint8_t buffer[10];
	uint64_t *addr;

	// Make sure cmd structure is valid
	if (cmd == NULL)
		return;

	// Randomly select a pending touch (or none)
	event = cmd->list;
	while (event != NULL) {
#ifdef PSL9
		if (((event->type == CMD_XLAT_RD_TOUCH) || (event->type == CMD_XLAT_WR_TOUCH))
		    && (event->state == MEM_IDLE)
		    && ((event->client_state != CLIENT_VALID)
			|| !allow_reorder(cmd->parms))) {
			break;
		}

#endif /* ifdef PSL9 */
		if (((event->type == CMD_TOUCH) || (event->type == CMD_WRITE))
		    && (event->state == MEM_IDLE)
		    && ((event->client_state != CLIENT_VALID)
			|| !allow_reorder(cmd->parms))) {
			break;
		}
		event = event->_next;
	}

	// Test for client disconnect
	if ((event == NULL) || ((client = _get_client(cmd, event)) == NULL))
		return;

	// Check that memory request can be driven to client
	if (client->mem_access != NULL)
		return;

	// Send memory touch request to client
	buffer[0] = (uint8_t) PSLSE_MEMORY_TOUCH;
	buffer[1] = (uint8_t) event->size;
	addr = (uint64_t *) & (buffer[2]);
	*addr = htonll(event->addr & CACHELINE_MASK);
	event->abort = &(client->abort);
	debug_msg("%s:MEMORY TOUCH tag=0x%02x addr=0x%016"PRIx64, cmd->afu_name,
		  event->tag, event->addr);
	if (put_bytes(client->fd, 10, buffer, cmd->dbg_fp, cmd->dbg_id,
		      event->context) < 0) {
		client_drop(client, PSL_IDLE_CYCLES, CLIENT_NONE);
	}
	event->state = MEM_TOUCH;
	client->mem_access = (void *)event;
	debug_cmd_client(cmd->dbg_fp, cmd->dbg_id, event->tag, event->context);
}

// Send pending interrupt to client as soon as possible
void handle_interrupt(struct cmd *cmd)
{
	struct cmd_event **head;
	struct cmd_event *event;
	struct client *client;
	uint16_t irq;
	uint8_t buffer[3];

	// Make sure cmd structure is valid
	if (cmd == NULL)
		return;

	// Send any interrupts to client immediately
	head = &cmd->list;
	while (*head != NULL) {
		if (((*head)->type == CMD_INTERRUPT) &&
		    ((*head)->state == MEM_IDLE))
			break;
		head = &((*head)->_next);
	}
	event = *head;

	// Test for client disconnect
	if ((event == NULL) || ((client = _get_client(cmd, event)) == NULL))
		return;

	// Send interrupt to client
	buffer[0] = PSLSE_INTERRUPT;
	irq = htons(cmd->irq);
	memcpy(&(buffer[1]), &irq, 2);
	event->abort = &(client->abort);
	debug_msg("%s:INTERRUPT irq=%d", cmd->afu_name, cmd->irq);
	if (put_bytes(client->fd, 3, buffer, cmd->dbg_fp, cmd->dbg_id,
		      event->context) < 0) {
		client_drop(client, PSL_IDLE_CYCLES, CLIENT_NONE);
	}
	debug_cmd_client(cmd->dbg_fp, cmd->dbg_id, event->tag, event->context);
	event->state = MEM_DONE;
}

void handle_buffer_data(struct cmd *cmd, uint32_t parity_enable)
{
	uint8_t *parity_check;
	int rc;
	struct cmd_event *event;
	int quadrant, byte;

	// Has struct been initialized?
	if ((cmd == NULL) || (cmd->buffer_read == NULL))
		return;

	// Check if buffer read data has returned from AFU
	event = cmd->buffer_read;
	rc = psl_get_buffer_read_data(cmd->afu_event, event->data,
				      event->parity);
	if (rc == PSL_SUCCESS) {
		debug_msg("%s:BUFFER READ tag=0x%02x", cmd->afu_name,
			  event->tag);
		for (quadrant = 0; quadrant < 4; quadrant++) {
			DPRINTF("DEBUG: Q%d 0x", quadrant);
			for (byte = 0; byte < CACHELINE_BYTES / 4; byte++) {
				DPRINTF("%02x", event->data[byte]);
			}
			DPRINTF("\n");
		}
	debug_msg("handle_buffer_data parity_enable is 0x%x ", parity_enable);
		if (parity_enable) {
			parity_check =
			    (uint8_t *) malloc(DWORDS_PER_CACHELINE / 8);
			generate_cl_parity(event->data, parity_check);
			if (strncmp((char *)event->parity,
				    (char *)parity_check,
				    DWORDS_PER_CACHELINE / 8)) {
				error_msg("Buffer read parity error tag=0x%02x",
					  event->tag);
			}
			free(parity_check);
		}
		// Free buffer interface for another event
		cmd->buffer_read = NULL;
#if defined PSL9 || defined PSL9lite
		if ((event->type == CMD_CAS_4B) || (event->type == CMD_CAS_8B)) { 
			event->state = MEM_CAS_OP;
			//printf("HANDLE_BUFFER_DATA read in op1/op2 \n");
			return;
		}
#endif
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
	struct cmd_event **head;
	struct cmd_event *event;
	struct client *client;
	uint64_t *addr;
	uint8_t *buffer;
	uint64_t offset;

	// Make sure cmd structure is valid
	if (cmd == NULL)
		return;

	// Send any ready write data to client immediately
	head = &cmd->list;
	while (*head != NULL) {
		if (((*head)->type == CMD_WRITE) &&
		    ((*head)->state == MEM_RECEIVED))
			break;
#if defined PSL9 || defined PSL9lite
		if ((((*head)->type == CMD_CAS_4B) || ((*head)->type == CMD_CAS_8B)) &&
		    ((*head)->state == MEM_CAS_WR))
			break;
#endif
		head = &((*head)->_next);
	}
	event = *head;

	// Test for client disconnect
	if ((event == NULL) || ((client = _get_client(cmd, event)) == NULL))
		return;

	// Check that memory request can be driven to client
	if (client->mem_access != NULL)
		return;

	// Send data to client and clear event to allow
	// the next buffer read to occur.  The request will now await
	// confirmation from the client that the memory write was
	// successful before generating a response.  The client
	// response will cause a call to either handle_aerror() or
	// handle_mem_return().
	buffer = (uint8_t *) malloc(event->size + 10);
	offset = event->addr & ~CACHELINE_MASK;
	buffer[0] = (uint8_t) PSLSE_MEMORY_WRITE;
	buffer[1] = (uint8_t) event->size;
	addr = (uint64_t *) & (buffer[2]);
	*addr = htonll(event->addr);
	memcpy(&(buffer[10]), &(event->data[offset]), event->size);
	event->abort = &(client->abort);
	debug_msg("%s:MEMORY WRITE tag=0x%02x size=%d addr=0x%016"PRIx64,
		  cmd->afu_name, event->tag, event->size, event->addr);
	if (put_bytes(client->fd, event->size + 10, buffer, cmd->dbg_fp,
		      cmd->dbg_id, client->context) < 0) {
		client_drop(client, PSL_IDLE_CYCLES, CLIENT_NONE);
	}
	debug_cmd_client(cmd->dbg_fp, cmd->dbg_id, event->tag, event->context);
	  	//printf ("handle_mem_write1: event->type is %2x, event->state is 0x%3x \n", event->type, event->state);
#if defined PSL9 || defined PSL9lite
	if ((event->type != CMD_CAS_4B) && (event->type != CMD_CAS_8B))
#endif
		event->state = MEM_REQUEST;
	  	//printf ("handle_mem_write2: event->type is %2x, event->state is 0x%3x \n", event->type, event->state);
	client->mem_access = (void *)event;
}

// Handle data returning from client for memory read
static void _handle_mem_read(struct cmd *cmd, struct cmd_event *event, int fd)
{
	uint8_t data[MAX_LINE_CHARS];
	uint64_t offset = event->addr & ~CACHELINE_MASK;
	
	// printf ("_handle_mem_read: event->type is %2x, event->state is 0x%3x \n", event->type, event->state);
#if defined PSL9 || defined PSL9lite
	if ((event->type == CMD_READ) ||
		 (((event->type == CMD_CAS_4B) || (event->type == CMD_CAS_8B)) && event->state != MEM_CAS_WR)) {
#else
	if (event->type == CMD_READ) {
#endif
	        // printf ("_handle_mem_read: CMD_READ \n" );
		// Client is returning data from memory read
		// printf("_handle_mem_read: before get bytes silent \n");
		if (get_bytes_silent(fd, event->size, data, cmd->parms->timeout,
			     event->abort) < 0) {
	        	debug_msg("%s:_handle_mem_read failed tag=0x%02x size=%d addr=0x%016"PRIx64,
				  cmd->afu_name, event->tag, event->size, event->addr);
			event->resp = PSL_RESPONSE_DERROR;
#if defined PSL9 || PSL9lite
			if ((event->type == CMD_CAS_4B) || (event->type == CMD_CAS_8B))
				event->resp = PSL_RESPONSE_CAS_INV;
#endif
			event->state = MEM_DONE;
			debug_cmd_update(cmd->dbg_fp, cmd->dbg_id, event->tag,
				 event->context, event->resp);
			return;
		}
		// printf("_handle_mem_read: AFTER get bytes silent \n");
		memcpy((void *)&(event->data[offset]), (void *)&data, event->size);
		generate_cl_parity(event->data, event->parity);
		event->state = MEM_RECEIVED;
	} 
#ifdef PSL9
        // have to expect data back from some AMO ops
	else if ((event->type == CMD_DMA_RD) || (event->type == CMD_DMA_WR_AMO)) {
		// Client is returning data from DMA memory read
                // printf( "_handle_mem_read: CMD_DMA_RD or CMD_DMA_WR_AMO \n" );
		if (get_bytes_silent(fd, event->dsize, data, cmd->parms->timeout,
			     event->abort) < 0) {
	        	debug_msg("%s:_handle_dma0_mem_read failed tag=0x%02x size=%d addr=0x%016"PRIx64,
				  cmd->afu_name, event->tag, event->dsize, event->addr);
			event->resp = PSL_RESPONSE_DERROR;
			event->state = MEM_DONE;
			debug_cmd_update(cmd->dbg_fp, cmd->dbg_id, event->tag,
				 event->context, event->resp);
			return;
		}
		// DMA return data goes at offset 0 in the event data instead of some other offset.
                // should we clear event->data first?
		memcpy((void *)event->data, (void *)&data, event->dsize);
		event->state = DMA_MEM_RESP;
	
	}
#endif /* ifdef PSL9 */
}

// Calculate page address in cached index for translation
static void _calc_index(struct cmd *cmd, uint64_t * addr, uint64_t * index)
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
	for (i = 0; i < PAGE_WAYS; i++) {
		if (cmd->page_entries.valid[index][i] &&
		    (cmd->page_entries.entry[index][i] != addr)) {
			cmd->page_entries.age[index][i]++;
			if (cmd->page_entries.age[index][i] > age) {
				age = cmd->page_entries.age[index][i];
				oldest = i;
			}
		}
		if (!cmd->page_entries.valid[index][i] && (empty == PAGE_WAYS)) {
			empty = i;
		}
		if (cmd->page_entries.valid[index][i] &&
		    (cmd->page_entries.entry[index][i] == addr)) {
			cmd->page_entries.age[index][i] = 0;
			set = 1;
		}
	}

	// Entry found and updated
	if (set)
		return;

	// Empty slot exists
	if (empty < PAGE_WAYS) {
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
	while ((i < PAGE_WAYS) && cmd->page_entries.valid[index][i] &&
	       (cmd->page_entries.entry[index][i] != addr)) {
		i++;
	}

	// Hit entry
	if ((i < PAGE_WAYS) && cmd->page_entries.valid[index][i])
		hit = 1;

	return hit;
}

// Decide what to do with a client memory acknowledgement
void handle_mem_return(struct cmd *cmd, struct cmd_event *event, int fd)
{
	struct client *client;

	// Test for client disconnect
	if ((event == NULL) || ((client = _get_client(cmd, event)) == NULL))
		return;

	debug_msg("%s:MEMORY ACK tag=0x%02x addr=0x%016"PRIx64, cmd->afu_name,
		  event->tag, event->addr);

	// Randomly cause paged response
	if (((event->type != CMD_WRITE) || (event->state != MEM_REQUEST)) &&
	    (client->flushing == FLUSH_NONE) && !_page_cached(cmd, event->addr)
	    && allow_paged(cmd->parms)) {
		if (event->type == CMD_READ)
			_handle_mem_read(cmd, event, fd);
		event->resp = PSL_RESPONSE_PAGED;
		event->state = MEM_DONE;
		client->flushing = FLUSH_PAGED;
		debug_cmd_update(cmd->dbg_fp, cmd->dbg_id, event->tag,
				 event->context, event->resp);
		return;
	}

	_update_age(cmd, event->addr);
#if defined PSL9 || defined PSL9lite
	if ((event->type == CMD_READ) ||
		 (((event->type == CMD_CAS_4B) || (event->type == CMD_CAS_8B)) && event->state != MEM_CAS_WR))
#else 
	if (event->type == CMD_READ)
#endif
		_handle_mem_read(cmd, event, fd);
#ifdef PSL9
 	// have to account for AMO fetch cmds with returned data
 	else if (event->type == CMD_DMA_RD) 	
		_handle_mem_read(cmd, event, fd);
 	else if (event->type == CMD_DMA_WR_AMO) {
                 if ((event->atomic_op & 0x3f) < 0x20)  
			_handle_mem_read(cmd, event, fd);
		 else
			event->state = MEM_DONE;
		}
	else if ((event->type == CMD_CAS_4B) || (event->type == CMD_CAS_8B)) 
			event->state = MEM_DONE;
		
#endif /* ifdef PSL9 */
	else if (event->type == CMD_TOUCH)
		event->state = MEM_DONE;
	else if (event->state == MEM_TOUCH)	// Touch before write
		event->state = MEM_TOUCHED;
	else			// Write after touch
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

//#ifdef PSL9
#if defined PSL9 || defined PSL9lite
void _handle_op1_op2_load(struct cmd *cmd, struct cmd_event *event)
{

	memcpy((char *)&event->cas_op1, (char *)event->data, sizeof(uint64_t));
	printf("op1 bytes 1-8 are 0x%016" PRIx64 " \n", event->cas_op1);
	//event->cas_op1 = ntohll (event->cas_op1);
	//printf("op1 bytes 1-8 are 0x%016" PRIx64 " \n", event->cas_op1);
	memcpy((char *)&event->cas_op2, (char *)event->data+8, sizeof(uint64_t));
	printf("op2 bytes 1-8 are 0x%016" PRIx64 " \n", event->cas_op2);
	//event->cas_op2 = ntohll (event->cas_op2);
	//printf("op2 bytes 1-8 are 0x%016" PRIx64 " \n", event->cas_op2);

}

void _handle_cas_op(struct cmd *cmd, struct cmd_event *event)
{
	uint32_t lvalue, op_A, op_1, op_2;
	uint64_t offset, op_Al;
	unsigned char op_size;

	offset = event->addr & ~CACHELINE_MASK;
	if (event->type == CMD_CAS_4B) {
		op_size = 4;
		memcpy((char *) &lvalue, (void *)&(event->data[offset]), op_size);
		op_A = (uint32_t)(lvalue);
		op_1 = (uint32_t) event->cas_op1;
		op_2 = (uint32_t) event->cas_op2;
		debug_msg("op_A is %08"PRIx32 " and op_1 is %08"PRIx32, op_A, op_1);
		if ((event->command == PSL_COMMAND_CAS_U_4B)  || 
		   ((event->command == PSL_COMMAND_CAS_E_4B) && (op_A == op_1 )) ||
		   ((event->command == PSL_COMMAND_CAS_NE_4B) && (op_A != op_1))) {
			memcpy((char *)(&event->data[offset]), (char *) &event->cas_op2, op_size);
			if (event->command == PSL_COMMAND_CAS_E_4B)
				event->resp = PSL_RESPONSE_COMP_EQ;
			else if (event->command == PSL_COMMAND_CAS_NE_4B)
				event->resp = PSL_RESPONSE_COMP_NEQ;
			else if ((event->command == PSL_COMMAND_CAS_U_4B) && (op_A == op_1))
				  event->resp = PSL_RESPONSE_COMP_EQ;
				else
				  event->resp = PSL_RESPONSE_COMP_NEQ;
			event->state = MEM_CAS_WR;
			debug_msg("HANDLE_CAS_OP CAS_U or CAS_E_4B IS EQUAL or CAS_NE_4B NOT EQUAL");
		} else	{
			if (event->command == PSL_COMMAND_CAS_E_4B)
				event->resp = PSL_RESPONSE_COMP_NEQ;
			else
				event->resp = PSL_RESPONSE_COMP_EQ;
			event->state = MEM_DONE;
			debug_msg("HANDLE_CAS_OP CAS_E_4B NOT EQUAL or CAS_NE_4B IS EQUAL");
		} 
	} else if (event->type == CMD_CAS_8B) {
		op_size = 8;
		debug_msg("op_1l is %016"PRIx64, event->cas_op1);
		debug_msg("op_2l is %016"PRIx64, event->cas_op2);
		memcpy((char *)&op_Al, (void *)&(event->data[offset]), op_size);
		debug_msg("op_Al is %016"PRIx64 " and op_1 is %016"PRIx64, op_Al,event->cas_op1);
		if ((event->command == PSL_COMMAND_CAS_U_8B)  || 
		   ((event->command == PSL_COMMAND_CAS_E_8B) && (op_Al == event->cas_op1 )) ||
		   ((event->command == PSL_COMMAND_CAS_NE_8B) && (op_Al != event->cas_op1))) {
			memcpy((char *)&event-> data[offset], (char *) &event->cas_op2, op_size);
			if (event->command == PSL_COMMAND_CAS_E_8B)
				event->resp = PSL_RESPONSE_COMP_EQ;
			else if (event->command == PSL_COMMAND_CAS_NE_8B)
				event->resp = PSL_RESPONSE_COMP_NEQ;
			else if ((event->command == PSL_COMMAND_CAS_U_8B) && (op_Al == event->cas_op1))
				  event->resp = PSL_RESPONSE_COMP_EQ;
				else
				  event->resp = PSL_RESPONSE_COMP_NEQ;
			event->state = MEM_CAS_WR;
			debug_msg("HANDLE_CAS_OP CAS_U or CAS_E_8B IS EQUAL or CAS_NE_8B NOT EQUAL");
		} else	{
			if (event->command == PSL_COMMAND_CAS_E_8B)
				event->resp = PSL_RESPONSE_COMP_NEQ;
			else
				event->resp = PSL_RESPONSE_COMP_EQ;
			event->state = MEM_DONE;
			debug_msg("HANDLE_CAS_OP CAS_E_8B NOT EQUAL or CAS_NE_8B IS EQUAL");
		} 
	}
}


void handle_caia2_cmds(struct cmd *cmd) 
{
	struct cmd_event **head;
	struct cmd_event *event;
	struct client *client;
	uint32_t this_itag;


	// Make sure cmd structure is valid
	if (cmd == NULL)
		return;

	// Look for any cmds to process 
	head = &cmd->list;
	while (*head != NULL) {
	  	//printf ("handle_caia2_cmds: head->type is %2x, head->state is 0x%3x \n", (*head)->type, (*head)->state);
	//first look for  CAS commands
		if (((*head)->type == CMD_CAS_4B) || ((*head)->type == CMD_CAS_8B))
			break;
#ifdef PSL9
	// next look for xlat read/write requests
		if ((((*head)->type == CMD_XLAT_RD) &&
		    ((*head)->state == DMA_ITAG_REQ)) |
		 (((*head)->type == CMD_XLAT_WR) &&
		    ((*head)->state == DMA_ITAG_REQ)))
			break;
	//next look for itag read/write abort requests
		if ((((*head)->type == CMD_ITAG_ABRT_RD) && ((*head)->state == MEM_TOUCHED)) |
		  (((*head)->type == CMD_ITAG_ABRT_WR) && ((*head)->state == MEM_TOUCHED))) 
			break;
	//next look for itag read/write touch requests
		if ((((*head)->type == CMD_XLAT_RD_TOUCH) && ((*head)->state != MEM_DONE)) |
		  (((*head)->type == CMD_XLAT_WR_TOUCH) && ((*head)->state != MEM_DONE))) 
			break;
	// finally look for incoming DMA op requests
		if (((*head)->state == DMA_PENDING) || ((*head)->state == DMA_PARTIAL))
			goto dmaop_chk;
#endif // ifdef PSL9 only
		head = &((*head)->_next);
	}
	event = *head;

	
// Test for client disconnect
	if ((event == NULL) || ((client = _get_client(cmd, event)) == NULL))
		return;
	//Process XLAT cmds and get them ready for handle_response to deal with
	switch (event->command) {
		// request read data from AFU buffer interface to get op1/op2, 
		// read cache line pointed to by EA. Compare op1 & [EA] and 
		// if required, update cacheline with op2 and write back to EA
		// return appropriate resp code to AFU
		case PSL_COMMAND_CAS_E_4B:
		case PSL_COMMAND_CAS_NE_4B:
		case PSL_COMMAND_CAS_U_4B:
		case PSL_COMMAND_CAS_E_8B:
		case PSL_COMMAND_CAS_NE_8B:
		case PSL_COMMAND_CAS_U_8B:
			event->size = CACHELINE_BYTES; // got to set up for cacheline read/write no matter what
			if (event->state == MEM_CAS_OP)  {
				_handle_op1_op2_load(cmd, event);
				event->state = MEM_CAS_RD;
				//printf("HANDLE_CAIA2_CMDS read in op1/op2 \n");
			} else if (event->state == MEM_RECEIVED) {
				//printf("HANDLE_CAIA2_CMDS calling handle cas op \n");
				_handle_cas_op(cmd, event);}
			break;
#ifdef PSL9
		case PSL_COMMAND_XLAT_RD_P0:
			event->itag = (rand() % 512);
			event->port = 0;
			//printf("in handle_caia2 for xlat_rd, address is 0x%016"PRIX64 "\n", event->addr);
			cmd->afu_event->response_dma0_itag = event->itag;
			cmd->afu_event->response_dma0_itag_parity = generate_parity(event->itag, ODD_PARITY);
			info_msg("dma0_itag for read is 0x%x", event->itag);
			event->state = DMA_ITAG_RET;
			break;
		case PSL_COMMAND_XLAT_WR_P0:
			event->itag = (rand() % 512);
			event->port = 0;
			//printf("in handle_caia2 for xlat_wr, address is 0x%016"PRIX64 "\n", event->addr);
			cmd->afu_event->response_dma0_itag = event->itag;
			cmd->afu_event->response_dma0_itag_parity = generate_parity(event->itag, ODD_PARITY);
			info_msg("dma0_itag for write is 0x%x", event->itag);
			event->state = DMA_ITAG_RET;
			break;
		case PSL_COMMAND_ITAG_ABRT_RD:
			/* if tag is in reserved state, go ahead and abort */
			/* otherwise, send back FAIL and warn msg  */
			this_itag = event->addr;
			debug_msg("NOW IN PSL_COMMAND_ITAG_ABRT_RD with this_itag = 0x%x ", this_itag);
			// Look for a matching itag to process immediately
			// check to see if dma op already started 
			head = &cmd->list;
			while (*head != NULL) {
				debug_msg ("in handle_caia2_cmds, processing ITAG abt read : head->type is %2x, head->state is 0x%x, head->itag is 0x%3x ", (*head)->type, (*head)->state, (*head)->itag);
				if (((*head)->state == DMA_ITAG_RET) &&
		    			((*head)->itag == this_itag)) 
					break;
				if (((*head)->state == DMA_PENDING) &&
		    			((*head)->itag == this_itag))
					break;
				head = &((*head)->_next);
			}
			if (*head == NULL) {  // didn't find this tag OR didn;t find in abortable state so fail
				event->resp = PSL_RESPONSE_FAILED;
				event->state = MEM_DONE;
				warn_msg("WRONG TAG or STATE: failed attempt to abort read dma0_itag 0x%x", event->itag);
				return;
				}
				// adjust credits count in psl_interface, not here
				(*head)->state = MEM_DONE;
				event->resp = PSL_RESPONSE_DONE;  
				event->state = MEM_DONE;
				info_msg("dma0_itag  0x%x for read aborted", this_itag);
				break;
		case PSL_COMMAND_ITAG_ABRT_WR:
			/* if tag is in reserved state, go ahead and abort */
			/* otherwise, send back FAIL and warn msg  */
			this_itag = event->addr;
			debug_msg("NOW IN PSL_COMMAND_ITAG_ABRT_WR with this_itag = 0x%x ", this_itag);
			// Look for a matching itag to process immediately
			// check to see if dma op already started 
			head = &cmd->list;
			while (*head != NULL) {
				debug_msg ("in handle_caia2_cmds, processing ITAG abt write : head->type is %2x, head->state is 0x%x, head->itag is 0x%3x ", (*head)->type, (*head)->state, (*head)->itag);
				if (((*head)->state == DMA_ITAG_RET) &&
		    			((*head)->itag == this_itag)) 
					break;
				if (((*head)->state == DMA_PENDING) &&
		    			((*head)->itag == this_itag))
					break;
				head = &((*head)->_next);
			}
			if (*head == NULL) {  // didn't find this tag OR not in abortable state so fail
				event->resp = PSL_RESPONSE_FAILED;
				event->state = MEM_DONE;
				warn_msg("WRONG TAG or STATE: failed attempt to abort write dma0_itag 0x%x", event->itag);
				return;
				}
				// will adjust credits count in psl_interface, not here
				(*head)->state = MEM_DONE;
		   		event->resp = PSL_RESPONSE_DONE;
				event->state = MEM_DONE;
				info_msg("dma0_itag  0x%x for write aborted", this_itag);
				break;
		case PSL_COMMAND_XLAT_RD_TOUCH:
		   	event->resp = PSL_RESPONSE_DONE;
			event->state = MEM_DONE;
			info_msg("XLAT_RD_TOUCH command doesn't return itag");
			break;
		case PSL_COMMAND_XLAT_WR_TOUCH:
		   	event->resp = PSL_RESPONSE_DONE;
			event->state = MEM_DONE;
			info_msg("XLAT_WR_TOUCH command doesn't return itag ");
			break;
#endif // ifdef PSL9 only
		default:
			warn_msg("Unsupported command 0x%04x", cmd);
			break;

	}
	return;
#ifdef PSL9
//here we search list of events to find one that has matching ITAG, then process
	dmaop_chk: event = *head;
		if (cmd->afu_event->dma0_dvalid == 1)  {
	if (event == NULL)
		printf ("why is event null but dma0_dvalid ??? \n");
	this_itag = cmd->afu_event->dma0_req_itag;
	// Look for a matching itag to process immediately
	head = &cmd->list;
	while (*head != NULL) {
		debug_msg ("in handle_caia2 cmds in dmaop_ck: head->type is %2x, head->itag is 0x%3x ", (*head)->type, (*head)->itag);
		if ((((*head)->type == CMD_XLAT_RD) &&
		    ((*head)->itag == this_itag)) |
		 (((*head)->type == CMD_XLAT_WR) &&
		    ((*head)->itag == this_itag)))
			break;
		head = &((*head)->_next);
	}
	if (*head != NULL) {
		event = *head;
		//Fill in event and set up for next steps
		event->itag = cmd->afu_event->dma0_req_itag;
		event->utag = cmd->afu_event->dma0_req_utag;
		event->dtype = cmd->afu_event->dma0_req_type;
		event->dsize = cmd->afu_event->dma0_req_size;
		// If DMA read, set up for subsequent handle_dma_mem_read
		if (event->dtype == DMA_DTYPE_RD_REQ) { 
			event->state = DMA_OP_REQ;
			event->type = CMD_DMA_RD;
		// check to make sure transaction will stay within a 4K boundary
		if ((event->addr+0x1000) <= (event->addr+(uint64_t)event->dsize))
			warn_msg("TRANSACTION WILL BE FRAGMENTED, it crosses 4K boundary!!! boundary= 0x%016"PRIx64" last byte= 0x%016"PRIx64, 
			(event->addr+0x1000), (event->addr +event->dsize));
		else
			debug_msg("TRANSACTION IS GOOD TO GO !!!! boundary= 0x%016"PRIx64" last byte= 0x%016"PRIx64,
			 (event->addr+0x1000), (event->addr +event->dsize));
			}
		// If DMA write, pull data in and set up for subsequent handle dma_mem_write
		// ALSO send over any AMO cmds that come across as dma wr
		if ((event->dtype == DMA_DTYPE_WR_REQ_128) && (event->dsize <= 128))  {
			debug_msg("copy to event buffer for write dma data  <= 128B type 1");
			event->state = DMA_OP_REQ;
			event->type = CMD_DMA_WR;
		  	memcpy((void *)&(event->data[0]), (void *)&(cmd->afu_event->dma0_req_data), event->dsize);
			debug_msg("%s:DMA0_VALID itag=0x%02x utag=0x%02x addr=0x%016"PRIx64" type = 0x%02x size=0x%02x", cmd->afu_name,
		  		event->itag, event->utag, event->addr, event->dtype, event->dsize);
			}
		if ((event->dtype == DMA_DTYPE_WR_REQ_128) && (event->dsize > 128))  {
			debug_msg("FIRST copy to event buffer for write dma data  > 128B type 1");
			event->state = DMA_PARTIAL;
			event->type = CMD_DMA_WR;
		  	memcpy((void *)&(event->data[0]), (void *)&(cmd->afu_event->dma0_req_data), 128);
			event->dpartial = 128;
			debug_msg("%s:DMA0_VALID itag=0x%02x utag=0x%02x addr=0x%016"PRIx64" type = 0x%02x total xfeed =0x%02x", cmd->afu_name,
		  		event->itag, event->utag, event->addr, event->dtype, event->dpartial);
			}
		if ((event->dtype == DMA_DTYPE_WR_REQ_MORE) && ((event->dsize - event->dpartial) > 128))  {
			debug_msg("copy to event buffer for write dma data  > 128B type 2");
			event->state = DMA_PARTIAL;
			event->type = CMD_DMA_WR;
		  	memcpy((void *)&(event->data[event->dpartial]), (void *)&(cmd->afu_event->dma0_req_data), 128);
			event->dpartial += 128;
			debug_msg("%s:DMA0_VALID itag=0x%02x utag=0x%02x addr=0x%016"PRIx64" type = 0x%02x total xfered =0x%02x", cmd->afu_name,
		  		event->itag, event->utag, event->addr, event->dtype, event->dpartial);
			}
		if ((event->dtype == DMA_DTYPE_WR_REQ_MORE) && ((event->dsize - event->dpartial) <= 128))  {
			debug_msg("FINAL copy to event buffer for write dma data  > 128B type 2");
			event->state = DMA_OP_REQ;
			event->type = CMD_DMA_WR;
		  	memcpy((void *)&(event->data[event->dsize - event->dpartial]), (void *)&(cmd->afu_event->dma0_req_data),
				 (event->dsize - event->dpartial));
			event->dpartial += (event->dsize - event->dpartial);;
			debug_msg("%s:DMA0_VALID itag=0x%02x utag=0x%02x addr=0x%016"PRIx64" type = 0x%02x total xfered =0x%02x", cmd->afu_name,
		  		event->itag, event->utag, event->addr, event->dtype, event->dpartial);
			}
		if ((event->dtype == DMA_DTYPE_ATOMIC) && (event->type == CMD_XLAT_RD))  
			error_msg("%s:INVALID REQ: DMA AMO W/XLAT_RD ITAG ITAG = 0x%3x DTYPE = %d ", cmd->afu_name, this_itag, event->dtype); 
		if ((event->dtype == DMA_DTYPE_ATOMIC) && (event->type == CMD_XLAT_WR))  {
			event->state = DMA_OP_REQ;
			event->type = CMD_DMA_WR_AMO;
			event->atomic_op = cmd->afu_event->dma0_atomic_op;
		  	memcpy((void *)&(event->data[0]), (void *)&(cmd->afu_event->dma0_req_data), 16);
			debug_msg("%s:DMA0_VALID itag=0x%02x utag=0x%02x addr=0x%016"PRIx64" type = 0x%02x size=0x%02x", cmd->afu_name,
		  		event->itag, event->utag, event->addr, event->dtype, event->dsize);
			}

		} else {
		error_msg("%s: DMA REQUEST RECEIVED WITH UNKNOWN/INVALID ITAG = 0x%3x", cmd->afu_name, this_itag); }
	cmd->afu_event->dma0_dvalid = 0;
	}
#endif // ifdef PSL9 only
//printf("cmd->afu_event->dma0_dvalid is 0x%2x \n", cmd->afu_event->dma0_dvalid);
   	return;
}
#endif /* ifdef PSL9 or PSL9lite*/

// Send a randomly selected pending response back to AFU
void handle_response(struct cmd *cmd)
{
	struct cmd_event **head;
	struct cmd_event *event;
	struct client *client;
	int rc;

	// Select a random pending response (or none)
	client = NULL;
	head = &cmd->list;
	while (*head != NULL) {
	        debug_msg( "%s:RESPONSE examine event @ 0x%016" PRIx64 ", command=0x%x, tag=0x%08x, type=0x%02x, state=0x%02x, resp=0x%x", 
			   cmd->afu_name,
			   (*head), 
			   (*head)->command, 
			   (*head)->tag, 
			   (*head)->type, 
			   (*head)->state, 
			   (*head)->resp ); 
		// Fast track error responses
		if ( ( (*head)->resp == PSL_RESPONSE_PAGED ) ||
		     ( (*head)->resp == PSL_RESPONSE_NRES ) ||
		     ( (*head)->resp == PSL_RESPONSE_NLOCK ) ||
		     ( (*head)->resp == PSL_RESPONSE_FAILED ) ||
		     ( (*head)->resp == PSL_RESPONSE_FLUSHED ) ) {
			event = *head;
			debug_msg( "%s:RESPONSE event @ 0x%016" PRIx64 ",drive response because resp is PSL_RESPONSE_error", cmd->afu_name, (*head) ); 
			goto drive_resp;
		}
#ifdef PSL9
		// if (dma write and we've sent utag sent status AND it wasn't AMO that has pending cpl resp), 
		// OR (dma write and it was AMO and we've sent cpl resp)
		// OR (itag was aborted),  we can remove this event 
		if ( ( ( (*head)->type == CMD_DMA_WR )     && ( (*head)->state == MEM_DONE ) ) ||
		     ( ( (*head)->type == CMD_DMA_WR_AMO ) && ( (*head)->state == MEM_DONE ) ) ||
		     ( ( (*head)->type == CMD_XLAT_WR )    && ( (*head)->state == MEM_DONE ) ) ) {
			//  update dma0_wr_credits IF CMD_DMA_WR or CMD_DMA_WR_AM0
			//if ((*head)->type != CMD_XLAT_WR)
			//	cmd->dma0_wr_credits++;
			event = *head;
			*head = event->_next;
			debug_msg( "%s:RESPONSE event @ 0x%016" PRIx64 ", free event and skip response because dma write related is done", 
				   cmd->afu_name, event ); 
			free(event->data);
			free(event->parity);
			free(event);
		        //printf("in handle_response and finally freeing original xlat/dma write event \n");
			return;
		} else if ( ( ( (*head)->type == CMD_DMA_RD )  && ( (*head)->state == DMA_CPL_SENT ) ) ||
			    ( ( (*head)->type == CMD_XLAT_RD ) && ( (*head)->state == MEM_DONE ) ) ) {
		        // if dma read and we've send completion data OR itag aborted , we can remove this event
			//  update dma0_rd_credits IF CMD_DMA_RD 
			//if ((*head)->type != CMD_XLAT_RD)
			//	cmd->dma0_rd_credits++;
			event = *head;
			*head = event->_next;
			debug_msg( "%s:RESPONSE event @ 0x%016" PRIx64 ", free event and skip response because dma read related is CPL or DONE", 
				   cmd->afu_name, event ); 
			free(event->data);
			free(event->parity);
			free(event);
	                //printf("in handle_response and finally freeing original xlat/dma read event \n");
			return;
		}


		if ( ( (*head)->type == CMD_XLAT_RD ) ||
		     ( (*head)->type == CMD_XLAT_WR ) ) {
				if ((*head)->state == DMA_ITAG_RET) {
					event = *head;
					event->resp = PSL_RESPONSE_DONE;
					debug_msg( "%s:RESPONSE event @ 0x%016" PRIx64 ", drive response because xlat type state was DMA_ITAG_RET", 
						   cmd->afu_name, event ); 
					goto drive_resp;
				} else {
					debug_msg( "%s:RESPONSE event @ 0x%016" PRIx64 ", skip response because xlat type state was not DMA_ITAG_RET", 
						   cmd->afu_name, (*head) ); 
					return;
				}
		}

#endif /* ifdef PSL9 */

		if (((*head)->state == MEM_DONE) && !allow_reorder(cmd->parms)) {
		        debug_msg( "%s:RESPONSE event @ 0x%016" PRIx64 ", drive response because MEM_DONE", 
				   cmd->afu_name, (*head) ); 
			break;
		}
		head = &((*head)->_next);
	}

	// Randomly decide not to drive response yet
	event = *head;
	if (event == NULL) {
	  // debug_msg( "%s:RESPONSE event @ 0x%016" PRIx64 " skipped because NULL", cmd->afu_name, event );
		return;
	}
	if ( ( event->client_state == CLIENT_VALID ) && !allow_resp( cmd->parms ) ) {
	        debug_msg( "%s:RESPONSE event @ 0x%016" PRIx64 " skipped because suppressed by allow_resp", cmd->afu_name, event );
		return;
	}
	// Test for client disconnect
	if ( ( client = _get_client( cmd, event ) ) == NULL ) {
	        debug_msg( "%s:RESPONSE event @ 0x%016" PRIx64 "skipped because client NULL", cmd->afu_name, event );
		return;
	}

	// Send response, remove command from list and free memory
	if ((event->resp == PSL_RESPONSE_PAGED) ||
	    (event->resp == PSL_RESPONSE_AERROR) ||
	    (event->resp == PSL_RESPONSE_DERROR)) {
	        debug_msg( "%s:RESPONSE flushing events because this one is an error", cmd->afu_name );
		client->flushing = FLUSH_FLUSHING;
		_update_pending_resps(cmd, PSL_RESPONSE_FLUSHED);
	}
 drive_resp:
	// debug - dump the event we picked...
	debug_msg( "%s:RESPONSE event @ 0x%016" PRIx64 ", command=0x%x, tag=0x%08x, type=0x%02x, state=0x%02x, resp=0x%x", 
		   cmd->afu_name,
		   event, 
		   event->command, 
		   event->tag, 
		   event->type, 
		   event->state, 
		   event->resp );

	// Check for pending buffer activity
	while (event == cmd->buffer_read) {
		if (cmd->afu_event->buffer_rdata_valid) {
			warn_msg("Application terminated while AFU write still active");
			_print_event(event);
			cmd->afu_event->buffer_rdata_valid = 0;
			cmd->buffer_read = NULL;
		}
		else {
			psl_signal_afu_model(cmd->afu_event);
			psl_get_afu_events(cmd->afu_event);
		}
	}
#if defined  PSL9 || defined PSL9lite
	rc = psl_response(cmd->afu_event, event->tag, event->resp, 1, 0, 0, cmd->pagesize, event->resp_extra);
	debug_msg("returning pagesize value of 0x%x and resp_extra = 0x%x" , cmd->pagesize, event->resp_extra);
#else
	rc = psl_response( cmd->afu_event, event->tag, event->resp, 1, 0, 0 );
#endif
	if (rc == PSL_SUCCESS) {
		debug_msg("%s:RESPONSE event @ 0x%016" PRIx64 ", sent tag=0x%02x code=0x%x", cmd->afu_name,
			  event, event->tag, event->resp);
		debug_cmd_response(cmd->dbg_fp, cmd->dbg_id, event->tag);
		if ( ( client != NULL ) && ( event->command == PSL_COMMAND_RESTART ) )
			client->flushing = FLUSH_NONE;
#ifdef PSL9
		// if this was an xlat cmd, don't want to free the event so add code to check - HMP
	        if ( ( event->type == CMD_XLAT_RD ) ||
		     ( event->type == CMD_XLAT_WR ) ) {
		  debug_msg( "%s:RESPONSE event @ 0x%016" PRIx64 ", set state dma pending and tag to deadbeef", 
			     cmd->afu_name,
			     event );
		  event->state = DMA_PENDING;
		  // do this to "free" the tag since AFU thinks it's free now
		  event->tag = 0xdeadbeef;
		  printf("DMA_PENDING set for event \n");
		  cmd->credits++; 
		} else { 
#endif /* ifdef PSL9 */
	          debug_msg( "%s:RESPONSE event @ 0x%016" PRIx64 ", free event", 
			     cmd->afu_name,
			     event );
		  *head = event->_next;
		  free(event->data);
		  free(event->parity);
		  free(event);
		  cmd->credits++;
#ifdef PSL9
		}
#endif /* ifdef PSL9 */
	} else {
		  debug_msg( "%s:RESPONSE event @ 0x%016" PRIx64 ", psl_response() failed", 
			     cmd->afu_name,
			     event );
	}
}

int client_cmd(struct cmd *cmd, struct client *client)
{
	int rc = 0;
	struct cmd_event *event = cmd->list;

	while (event != NULL) {
		if (event->context != client->context) {
			// Event is not for this client
			event = event->_next;
			continue;
		}
		if ((client->state == CLIENT_NONE) &&
		    (event->state != MEM_DONE)) {
			// Client dropped, terminate event
			event->state = MEM_DONE;
			if ((event->type == CMD_READ) ||
			    (event->type == CMD_WRITE) ||
			    (event->type == CMD_TOUCH)) {
				event->resp = PSL_RESPONSE_FAILED;
			}
			event = event->_next;
			continue;
		}
		if (client->state == CLIENT_VALID) {
			// Event is for client in valid state
			return 1;
		}
		event = event->_next;
	}
	return rc;
}
