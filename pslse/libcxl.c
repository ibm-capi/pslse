/*
 * Copyright 2014 International Business Machines
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

#include <malloc.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <assert.h>

#include "libcxl.h"
#include "libcxl_internal.h"
#include "psl_interface/psl_interface.h"

#define PSA_REQUIRED_MASK 0x0100000000000000L

#ifdef DEBUG
#define DPRINTF(...) printf(__VA_ARGS__)
#else
#define DPRINTF(...)
#endif


/*
 * Simulation parms
 */
// TODO: Clean this up with better method

#define PAGED_RANDOMIZER 5	// Percent chance of getting paged response

#define RESP_RANDOMIZER 5	// Setting to 1 achieves fastest responses,
				// Large values increase response delays
				// Zero is an illegal value

/*
 * System constants
 */

#define ODD_PARITY 1		// 1=Odd parity, 0=Even parity
#define MAX_LINE_CHARS 1024
#define PSL_TAGS 256
#define MAX_CREDITS 64
#define CACHELINE_BYTES 128
#define DWORDS_PER_CACHELINE 16
#define BYTES_PER_DWORD 8
#define WORD_OFFSET 4

/*
 * Enumerations
 */

enum PSL_STATE {
	PSL_INIT,
	PSL_RUNNING,
	PSL_FLUSHING,
	PSL_LOCK,
	PSL_NLOCK,
	PSL_DONE
};

enum AFU_STATE {
	AFU_IDLE,
	AFU_RESET,
	AFU_REQUEST,
	AFU_PENDING
};

enum RESP_TYPE {
	RESP_NORMAL,
	RESP_UNLOCK
};

/*
 * Structures
 */

struct afu_command {
	int request;
	uint32_t code;
	uint64_t addr;
};

struct afu_mmio {
	int request;
	int rnw;
	uint32_t dw;
	uint32_t addr;
	uint64_t data;
	uint32_t parity;
	uint32_t desc;
};

struct afu_req {
	enum {
		REQ_EMPTY = 0,
		REQ_READ,
		REQ_WRITE,
		REQ_READ_PRELIM,
		REQ_READ_WAIT_BUFFER,
		REQ_READ_GOT_BUFFER,
	} type;
	uint32_t tag;
	uint32_t size;
	uint8_t *addr;
	uint8_t resp_type;
};

struct afu_resp {
	uint32_t tag;
	uint32_t code;
	struct afu_resp *_next;
};

struct cxl_event_wrapper {
	struct cxl_event *event;
	struct cxl_event_wrapper *_next;
};

struct psl_status {
	struct AFU_EVENT *event;
	volatile struct cxl_event_wrapper *event_list;
	volatile struct afu_command cmd;
	volatile struct afu_mmio mmio;
	struct afu_resp *first_resp;
	struct afu_resp *last_resp;
	volatile int psl_state;
	unsigned int max_ints;
	unsigned int credits;
	int active_tags[PSL_TAGS];
	struct afu_req buffer_req[MAX_CREDITS];
	struct afu_req *buffer_read;
};

static struct psl_status status;

/*
 * Helper functions
 */

static int timeout_occured = 0;
static void alarm_handler(int signal)
{
	timeout_occured = 1;
}

static void start_timeout(unsigned int timeout_seconds)
{
	signal(SIGALRM, alarm_handler);
	timeout_occured = 0;
	alarm(timeout_seconds);
}

static void short_delay () {
	struct timespec ts;
	ts.tv_sec = 0;
	ts.tv_nsec = 4; // 250MHz = 4ns cycle time
	nanosleep(&ts, &ts);
}

#define wait_with_timeout(cond, timeout_seconds, message)   ({ \
	start_timeout(timeout_seconds);			       \
	while(cond && !timeout_occured) short_delay();	       \
							       \
	if (timeout_occured) {				       \
		fprintf(stderr, "TIMEOUT: " message "\n");     \
		catastrophic_error(afu);		       \
	}						       \
})

static int testmemaddr(uint8_t *memaddr) {
	int fd[2];
	int ret = 0;
	if (pipe(fd) >= 0) {
		if (write(fd[1], memaddr, 1) > 0)
			ret = 1;
	}

	close (fd[0]);
	close (fd[1]);

	return ret;
}

static uint8_t generate_parity (uint64_t data, uint8_t odd) {
	uint8_t parity = odd;
	// While at least 1 bit is set
	while (data) {
		// Invert parity bit
		parity = 1-parity;
		// Zero out least significant bit that is set to 1
		data &= data-1;
	}
	return parity;
}

static void generate_cl_parity (uint8_t *data, uint8_t *parity) {
	int i;
	uint64_t dw;
	uint8_t p;

	// Walk each double word (dword) in cacheline
	for (i=0; i<DWORDS_PER_CACHELINE; i++) {
		// Copy dword of data into uint64_t dw
		memcpy(&dw, &(data[BYTES_PER_DWORD*i]), BYTES_PER_DWORD);
		// Initialize parity entry to 0 when starting parity byte
		if ((i%BYTES_PER_DWORD)==0)
			parity[i/BYTES_PER_DWORD]=0;
		// Shift previously calculated parity bits left
		parity[i/BYTES_PER_DWORD]<<=1;
		// Generate parity bit for this dword
		p=generate_parity(dw, ODD_PARITY);
		parity[i/BYTES_PER_DWORD]+=p;
	}
}

/*
 * PSL thread functions
 */

static void catastrophic_error (struct cxl_afu_h* afu) {
	fflush (stdout);
	fprintf (stderr, "CATASTROPHIC ERROR: Shutting down!\n");
	fflush (stderr);
	afu->running = 0;
	afu->catastrophic = 1;
	status.psl_state = PSL_DONE;
}

static int add_interrupt (volatile struct cxl_event_wrapper **head,
			  uint64_t irq) {
	struct cxl_event_wrapper *new_event;

	// Check for legal interrupt number
	irq &= 0x7FFL;
	if (!irq || (irq > status.max_ints))
		return 1;

	// Find end of list searching for duplicates
	if (*head) {
		if ((*head)->event->irq.irq == (__u16) irq)
			return 1;
		return add_interrupt ((volatile struct cxl_event_wrapper **)
				      &((*head)->_next), irq);
	}

	new_event = (struct cxl_event_wrapper *)
		    malloc (sizeof (struct cxl_event_wrapper));
	new_event->event = (struct cxl_event *)
		    malloc (sizeof (struct cxl_event));
	new_event->event->header.type = CXL_EVENT_AFU_INTERRUPT;
	new_event->event->header.size = 16;
	new_event->event->header.process_element = 0;
	new_event->event->irq.irq = (__u16) irq;
	*head = new_event;
	return 0;
}

static void update_pending_resps (uint32_t code) {
	struct afu_resp *resp;
	resp = status.first_resp;
	while (resp != NULL) {
		resp->code = code;
		resp = resp->_next;
	}
}

static void add_resp (uint32_t tag, uint32_t code) {
	struct afu_resp *resp;
	resp = (struct afu_resp *) malloc (sizeof (struct afu_resp));
	resp->tag = tag;
	resp->code = code;
	resp->_next = NULL;
	if (status.last_resp == NULL) {
		status.first_resp = resp;
		status.last_resp = resp;
	}
	else {
		status.last_resp->_next = resp;
		status.last_resp = resp;
	}
}

static void push_resp () {
	if (status.first_resp == NULL)
		return;

	if (psl_response (status.event, status.first_resp->tag,
	    status.first_resp->code, 1, 0, 0) == PSL_SUCCESS) {
		DPRINTF("Response ");
		switch (status.first_resp->code) {
		case PSL_RESPONSE_DONE:
			DPRINTF("DONE");
			break;
		case PSL_RESPONSE_AERROR:
			DPRINTF("AERROR");
			break;
		case PSL_RESPONSE_DERROR:
			DPRINTF("DERROR");
			break;
		case PSL_RESPONSE_NLOCK:
			DPRINTF("NLOCK");
			break;
		case PSL_RESPONSE_NRES:
			DPRINTF("NRES");
			break;
		case PSL_RESPONSE_FLUSHED:
			DPRINTF("FLUSHED");
			break;
		case PSL_RESPONSE_FAULT:
			DPRINTF("FAULT");
			break;
		case PSL_RESPONSE_FAILED:
			DPRINTF("FAILED");
			break;
		case PSL_RESPONSE_PAGED:
			DPRINTF("PAGED");
			break;
		case PSL_RESPONSE_CONTEXT:
			DPRINTF("CONTEXT");
			break;
		default:
			DPRINTF("UNKNOWN");
		}
		DPRINTF(" tag=0x%02x\n", status.first_resp->tag);
		struct afu_resp *temp;
		status.active_tags[status.first_resp->tag] = 0;
		temp = status.first_resp;
		status.first_resp = status.first_resp->_next;
		if (status.first_resp == NULL) {
			status.last_resp = NULL;
		}
		free (temp);
		++status.credits;
	}
}

static int find_buffer_req(int empty)
{
	int j;
	int i = rand() % MAX_CREDITS;

	for (j = 0; j < MAX_CREDITS; j++) {
		if ((status.buffer_req[i].type == REQ_EMPTY) == empty)
			break;
		i++;
		i %= MAX_CREDITS;
	}

	return i;
}

static void add_buffer_req(int type, uint32_t tag, uint32_t size,
			   uint8_t *addr, uint8_t resp_type)
{
	int i = find_buffer_req(1);

	// Sanity check -- this should never occur
	assert(status.buffer_req[i].type == REQ_EMPTY);

	status.buffer_req[i].type = type;
	status.buffer_req[i].tag = tag;
	status.buffer_req[i].size = size;
	status.buffer_req[i].addr = addr;
	status.buffer_req[i].resp_type = resp_type;
}

static int check_mem_addr(struct afu_req *req)
{
	if (testmemaddr(req->addr))
		return 0;

	fflush(stdout);
	fprintf(stderr, "AFU attempted ");
	if (req->type == REQ_WRITE)
		fprintf(stderr, "write");
	else
		fprintf(stderr, "read");
	fprintf(stderr, " to invalid address 0x");
	fprintf(stderr, "%016llx", (long long) req->addr);
	fprintf(stderr, "\n");
	fflush(stderr);
	add_resp(req->tag, PSL_RESPONSE_AERROR);
	status.psl_state = PSL_FLUSHING;
	req->type = REQ_EMPTY;

	return 1;
}

static int check_flushing(struct afu_req *req)
{
	if (status.psl_state != PSL_FLUSHING)
		return 0;

	add_resp(req->tag, PSL_RESPONSE_FLUSHED);
	req->type = REQ_EMPTY;

	return 1;
}

static int check_paged(struct afu_req *req)
{
	if (!PAGED_RANDOMIZER || rand() % PAGED_RANDOMIZER)
		return 0;

	add_resp(req->tag, PSL_RESPONSE_PAGED);
	status.psl_state = PSL_FLUSHING;
	status.buffer_read = NULL;
	req->type = REQ_EMPTY;

	return 1;
}

static void do_buffer_write(uint8_t *addr, uint32_t tag, int prelim)
{
	uint8_t parity[DWORDS_PER_CACHELINE/8];
	DPRINTF("Buffer %s Write tag=0x%02x\n", prelim ? "Prelim" : "", tag);
	generate_cl_parity(addr, parity);
	psl_buffer_write(status.event, tag, (uint64_t) addr,
			 CACHELINE_BYTES, addr, parity);
}

static void handle_buffer_req(struct cxl_afu_h* afu)
{
	enum {
		// A prelim_op is n extra buffer read/write which occurs before
		// sending the completion
		PRELIM_OP,
		COMPLETE,
		DELAY_START,
		DELAY_END = 15,
		MAX_OPS
	} op = rand() % MAX_OPS;

	//7 in 8 chance to delay so more commands can come
	if (op >= DELAY_START && op <= DELAY_END)
		return;

	int i = find_buffer_req(0);
	struct afu_req *req = &status.buffer_req[i];

	if (req->type == REQ_EMPTY)
		return;

	if (check_flushing(req)) return;
	if (check_mem_addr(req)) return;
	if (check_paged(req)) return;

	if (req->type == REQ_READ) {
		if (status.buffer_read != NULL)
			return;

		DPRINTF("Buffer Read tag=0x%02x\n", req->tag);
		psl_buffer_read(status.event, req->tag, (uint64_t) req->addr,
				CACHELINE_BYTES);
		status.buffer_read = req;
		if (op == COMPLETE)
		    req->type = REQ_READ_WAIT_BUFFER;
		else
		    req->type = REQ_READ_PRELIM;

	} else if (req->type == REQ_READ_GOT_BUFFER) {
		add_resp(req->tag, PSL_RESPONSE_DONE);
		req->type = REQ_EMPTY;
	} else if (req->type == REQ_WRITE && op == PRELIM_OP) {
		uint8_t prelim_data[CACHELINE_BYTES];
		memset(prelim_data, 0xFF, sizeof(prelim_data));
		do_buffer_write(prelim_data, req->tag, 1);
	} else if (req->type == REQ_WRITE && op == COMPLETE) {
		do_buffer_write(req->addr, req->tag, 0);

		if (status.psl_state==PSL_NLOCK) {
			add_resp(req->tag, PSL_RESPONSE_NLOCK);
		} else {
			add_resp(req->tag, PSL_RESPONSE_DONE);
		}

		req->type = REQ_EMPTY;
	}
}

static void handle_aux2_change (struct cxl_afu_h* afu) {
	status.event->aux2_change = 0;

	// AFU started running
	if (status.event->job_running)
		afu->running = 1;

	// AFU done
	if (status.event->job_done) {
		if (status.event->job_running) {
			fflush (stdout);
			fprintf (stderr, "ERROR: ");
			fprintf (stderr, "jdone=1 while jrunning=1!");
			fflush (stderr);
		}
		if (status.cmd.request==AFU_RESET)
			status.cmd.request = AFU_IDLE;
		afu->running = 0;
	}

	if (status.event->parity_enable)
		afu->parity_enable = 1;
	else
		afu->parity_enable = 0;

	DPRINTF("AUX2 paren=%d jrunning=%d jdone=%d", afu->parity_enable,
		status.event->job_running, status.event->job_done);
	if (status.event->job_done) {
		DPRINTF(" jerror=0x%016llx",
			(long long) status.event->job_error);
	}
	DPRINTF("\n");
}

static void handle_mmio_acknowledge (struct cxl_afu_h* afu) {
	DPRINTF("MMIO Acknowledge\n");
	status.mmio.request = AFU_IDLE;
	if (afu->parity_enable && status.event->mmio_read &&
	    (status.mmio.parity !=
	     generate_parity(status.mmio.data, ODD_PARITY))) {
		fflush (stdout);
		fprintf (stderr, "ERROR: MMIO read data parity error\n");
		fprintf (stderr, " Data:0x%016llx\n",
			 (long long) status.mmio.data);
		fprintf (stderr, " Parity:%d\n", status.mmio.parity);
		fflush (stderr);
		status.mmio.data = ~0ull;
	}
}

static void handle_buffer_read (struct cxl_afu_h* afu) {
	uint64_t offset;
	uint8_t *buffer;
	uint8_t parity[DWORDS_PER_CACHELINE/8];
	uint8_t parity_check[DWORDS_PER_CACHELINE/8];
	unsigned i;
	struct afu_req *req = status.buffer_read;

	if (req == NULL)
		return;

	buffer = (uint8_t *) malloc (CACHELINE_BYTES);
	if (psl_get_buffer_read_data (status.event, buffer, parity)
	    != PSL_SUCCESS)
		goto cleanup;

	offset = (uint64_t) req->addr;
	offset &= 0x7Fll;

	if (req->type != REQ_READ_PRELIM) {
		memcpy (req->addr, &(buffer[offset]), req->size);

		if ((req->resp_type==RESP_UNLOCK) &&
		    ((status.psl_state==PSL_LOCK) ||
		     (status.psl_state==PSL_NLOCK))) {
			DPRINTF("Lock sequence completed\n");
			status.psl_state = PSL_RUNNING;
		}
	}

	generate_cl_parity(buffer, parity_check);
	if (afu->parity_enable &&
	    memcmp(parity, parity_check, sizeof(parity))) {
		fflush (stdout);
		fprintf (stderr, "ERROR: Buffer read parity error");
		fprintf (stderr, ", tag=0x%02x\n", req->tag);
		for (i=0; i<CACHELINE_BYTES; i++) {
			if (!(i%32))
				fprintf (stderr, "\n  0x");
			fprintf (stderr, "%02x", buffer[i]);
		}
		fprintf (stderr, "\n  0x");
		for (i=0; i<DWORDS_PER_CACHELINE/8; i++) {
			fprintf (stderr, "%02x", parity[i]);
		}
		fprintf (stderr, "\n");
		fflush (stderr);
		add_resp (req->tag, PSL_RESPONSE_DERROR);
		status.psl_state = PSL_FLUSHING;
		goto cleanup;
	}

	if (req->type != REQ_READ_PRELIM)
		req->type = REQ_READ_GOT_BUFFER;
	else
		req->type = REQ_READ;

	status.buffer_read = NULL;

cleanup:
	free(buffer);
}

static void cmd_parity_error (const char *msg, uint64_t value, uint64_t parity) {
	fflush (stdout);
	fprintf (stderr, "ERROR: Common %s parity error", msg);
	fprintf (stderr, " 0x%llx", (long long) value);
	fprintf (stderr, ",%d\n", (int) parity);
	fflush (stderr);
}

static int cmd_error_check (struct cxl_afu_h* afu) {
	unsigned fail;
	uint32_t tag, tagpar, cmd, cmdpar;
	uint64_t addr;
	uint64_t addrpar;

	status.event->command_valid = 0;
	tag = status.event->command_tag;
	tagpar = status.event->command_tag_parity;
	cmd = status.event->command_code;
	cmdpar = status.event->command_code_parity;
	addr = status.event->command_address;
	addrpar = status.event->command_address_parity;

	if (!afu->running) {
		fflush (stdout);
		fprintf (stderr, "ERROR: Command without jrunning=1,");
		fprintf (stderr, " tag=0x%02x\n", tag);
		fflush (stderr);
	}

	if (afu->parity_enable) {
		fail = 0;
		if (addrpar != generate_parity(addr, ODD_PARITY)) {
			cmd_parity_error ("address", addr, addrpar);
			fail = 1;
		}
		if (tagpar != generate_parity(tag, ODD_PARITY)) {
			cmd_parity_error ("tag", (uint64_t) tag,
					  (uint64_t) tagpar);
			fail = 1;
		}
		if (cmdpar != generate_parity(cmd, ODD_PARITY)) {
			cmd_parity_error ("code", (uint64_t) cmd,
					  (uint64_t) cmdpar);
			fail = 1;
		}
		if (fail) {
			add_resp (tag, PSL_RESPONSE_FAILED);
			return 1;
		}
	}

	return 0;
}

static void handle_command_valid (struct cxl_afu_h* afu) {
	uint32_t tag, size, cmd;
	uint64_t addr;
	uint8_t *addrptr;
	uint8_t resp_type;

	status.event->command_valid = 0;
	tag = status.event->command_tag;
	size = status.event->command_size;
	cmd = status.event->command_code;
	addr = status.event->command_address;
	addrptr = (uint8_t *) status.event->command_address;

	DPRINTF("Command %04x tag=0x%02x\n", cmd, tag);

	// Check for parity errors on command
	if (cmd_error_check (afu))
		return;

	// Check for valid tag
	if (status.active_tags[tag]) {
		fflush (stdout);
		fprintf (stderr, "ERROR: Tag already in use:");
		fprintf (stderr, "0x%02x\n", tag);
		fflush (stderr);
		add_resp (tag, PSL_RESPONSE_FAILED);
		catastrophic_error (afu);
		return;
	}
	status.active_tags[tag] = 1;

	// Check credits
	if (!status.credits) {
		fflush (stdout);
		fprintf (stderr, "ERROR: No credits left for command");
		fprintf (stderr, " tag=0x%02x\n", tag);
		fflush (stderr);
		add_resp (tag, PSL_RESPONSE_FAILED);
		return;
	}
	--status.credits;

	// Check if PSL is flushing commands
	if ((status.psl_state==PSL_FLUSHING) && (cmd != PSL_COMMAND_RESTART)) {
		add_resp (tag, PSL_RESPONSE_FLUSHED);
		return;
	}

	// Check for lock violations
	if (((status.psl_state==PSL_LOCK) &&
	     (cmd !=PSL_COMMAND_WRITE_UNLOCK)) ||
	    (status.psl_state==PSL_NLOCK)) {
		add_resp (tag, PSL_RESPONSE_NLOCK);
		status.psl_state=PSL_NLOCK;
		update_pending_resps (PSL_RESPONSE_NLOCK);
		DPRINTF("Dumping lock intervening command, tag=0x%02x\n", tag);
		return;
	}

	// Parse command
	resp_type = RESP_NORMAL;
	switch (cmd) {
	// Interrupt
	case PSL_COMMAND_INTREQ:
		printf ("AFU interrupt command received\n");
		if (add_interrupt (&(status.event_list), addr)) {
			add_resp (tag, PSL_RESPONSE_FAILED);
		}
		else {
			add_resp (tag, PSL_RESPONSE_DONE);
		}
		break;
	// Restart
	case PSL_COMMAND_RESTART:
		status.psl_state = PSL_RUNNING;
		DPRINTF("AFU restart command received\n");
		add_resp (tag, PSL_RESPONSE_DONE);
		break;
	case PSL_COMMAND_LOCK:
		update_pending_resps (PSL_RESPONSE_NLOCK);
		status.psl_state = PSL_LOCK;
		DPRINTF("Starting lock sequence, tag=0x%02x\n", tag);
		break;
	case PSL_COMMAND_UNLOCK:
		resp_type = RESP_UNLOCK;
		break;
	// Memory Reads
	case PSL_COMMAND_READ_CL_LCK:
		update_pending_resps (PSL_RESPONSE_NLOCK);
		status.psl_state = PSL_LOCK;
		DPRINTF("Starting lock sequence, tag=0x%02x\n", tag);
	case PSL_COMMAND_READ_CL_NA:
	case PSL_COMMAND_READ_CL_S:
	case PSL_COMMAND_READ_CL_M:
	case PSL_COMMAND_READ_CL_RES:
	case PSL_COMMAND_READ_PNA:
	case PSL_COMMAND_READ_LS:
	case PSL_COMMAND_READ_LM:
	case PSL_COMMAND_RD_GO_S:
	case PSL_COMMAND_RD_GO_M:
	case PSL_COMMAND_RWITM:
		DPRINTF("Read command size=%d tag=0x%02x\n", size, tag);
		add_buffer_req(REQ_WRITE, tag, size, addrptr,  resp_type);
		break;
	// Memory Writes
	case PSL_COMMAND_WRITE_UNLOCK:
		resp_type = RESP_UNLOCK;
	case PSL_COMMAND_WRITE_C:
	case PSL_COMMAND_WRITE_MI:
	case PSL_COMMAND_WRITE_MS:
	case PSL_COMMAND_WRITE_NA:
	case PSL_COMMAND_WRITE_INJ:
	case PSL_COMMAND_WRITE_LM:
		DPRINTF("Write command size=%d, tag=0x%02x\n", size, tag);
		add_buffer_req(REQ_READ, tag, size, addrptr,  resp_type);
		break;
	case PSL_COMMAND_TOUCH_I:
	case PSL_COMMAND_TOUCH_S:
	case PSL_COMMAND_TOUCH_M:
	case PSL_COMMAND_TOUCH_LS:
	case PSL_COMMAND_TOUCH_LM:
	case PSL_COMMAND_PUSH_I:
	case PSL_COMMAND_PUSH_S:
	case PSL_COMMAND_INVALIDATE:
	case PSL_COMMAND_CASTOUT_I:
	case PSL_COMMAND_CASTOUT_S:
	case PSL_COMMAND_CLAIM_M:
	case PSL_COMMAND_CLAIM_U:
	case PSL_COMMAND_FLUSH:
	case PSL_COMMAND_EVICT_I:
		add_resp (tag, PSL_RESPONSE_DONE);
		break;
	default:
		fflush (stdout);
		fprintf (stderr, "ERROR: Command currently unsupported");
		fprintf (stderr, " 0x%04x\n", cmd);
		fflush (stderr);
		++status.credits;
		break;
	}
}

static void handle_psl_events (struct cxl_afu_h* afu) {
	// AUX2 signals changed
	if (status.event->aux2_change)
		handle_aux2_change (afu);

	// MMIO acknowledge received
	if (psl_get_mmio_acknowledge (status.event, (uint64_t *)
	    &(status.mmio.data), (uint32_t *) &(status.mmio.parity)) ==
	    PSL_SUCCESS)
		handle_mmio_acknowledge (afu);

	// Command received
	if (status.event->command_valid)
		handle_command_valid (afu);
}


static void *psl(void *ptr) {
	struct cxl_afu_h *afu = (struct cxl_afu_h *)ptr;

	while (status.psl_state != PSL_DONE) {
	        if (status.psl_state == PSL_INIT) {
			psl_signal_afu_model (status.event);
	        	status.psl_state = PSL_RUNNING;
		}
		if (status.cmd.request==AFU_REQUEST) {
			if (psl_job_control (status.event, status.cmd.code,
			    status.cmd.addr) == PSL_SUCCESS) {
				DPRINTF("Job 0x%02x\n", status.cmd.code);
				if (status.cmd.code == PSL_JOB_RESET)
					status.cmd.request = AFU_RESET;
				else
					status.cmd.request = AFU_PENDING;
				continue;
			}
		}
		else if (status.mmio.request == AFU_REQUEST) {
			if (status.mmio.rnw) {
				if (psl_mmio_read (status.event, status.mmio.dw,
				    status.mmio.addr, status.mmio.desc) ==
				    PSL_SUCCESS) {
					DPRINTF("MMIO Read %d\n", status.mmio.addr);
					status.mmio.request = AFU_PENDING;
					continue;
				}
			}
			else {
				if (psl_mmio_write (status.event,
						    status.mmio.dw,
						    status.mmio.addr,
						    status.mmio.data,
						    status.mmio.desc) ==
						    PSL_SUCCESS) {
					DPRINTF("MMIO Write %d\n", status.mmio.addr);
					status.mmio.request = AFU_PENDING;
					continue;
				}
			}
		}
		if (!(rand() % RESP_RANDOMIZER))
			push_resp();
		psl_signal_afu_model (status.event);
		if (psl_get_afu_events (status.event) > 0) {
			handle_psl_events (afu);
		}

		handle_buffer_read(afu);
		handle_buffer_req(afu);
	}

	pthread_exit(NULL);
}

/*
 * libcxl functions
 */

struct cxl_afu_h * cxl_afu_open_dev(char *path) {
	char *x, *comment, *afu_id, *host, *port_str;
	struct cxl_afu_h *afu;
	FILE *fp;
	char hostdata[MAX_LINE_CHARS];
	int port;
	uint64_t value;

	// Isolate AFU id from full path
	x = strrchr (path, '/');
	x++;

	// Allocate AFU struct
	afu = (struct cxl_afu_h *) malloc (sizeof (struct cxl_afu_h));
	if (!afu) {
		perror ("malloc");
		errno = ENOMEM;
		return NULL;
	}

	// Allocate AFU_EVENT struct
	status.event = (struct AFU_EVENT *) malloc (sizeof (struct AFU_EVENT));
	if (!status.event ) {
		perror ("malloc");
		free (afu);
		errno = ENOMEM;
		return NULL;
	}
	psl_event_reset (status.event);

	// Connect to AFU server
	fp = fopen ("shim_host.dat", "r");
	if (!fp) {
		perror ("fopen:shim_host.dat");
		free (status.event);
		free (afu);
		errno = ENODEV;
		return NULL;
	}
	afu_id = x+1;
	host = NULL;
	port_str = NULL;
	while (strcmp (afu_id, x) && fgets (hostdata, MAX_LINE_CHARS, fp)) {
		afu_id = hostdata;
		comment = strchr(hostdata, '#');
		if (comment)
			continue;
		host = strchr(hostdata, ',');
		if (host) {
			*host = '\0';
			++host;
		}
		else {
			fflush (stdout);
			fprintf (stderr, "Invalid format in shim_host.dat.");
			fprintf (stderr, "  Expected ',' :%s\n", hostdata);
			fflush (stderr);
			fclose (fp);
			free (status.event);
			free (afu);
			errno = ENODEV;
			return NULL;
		}
		port_str = strchr(host, ':');
		if (port_str) {
			*port_str = '\0';
			++port_str;
		}
		else {
			fflush (stdout);
			fprintf (stderr, "Invalid format in shim_host.dat.");
			fprintf (stderr, "  Expected ':' :%s\n", hostdata);
			fflush (stderr);
			fclose (fp);
			free (status.event);
			free (afu);
			errno = ENODEV;
			return NULL;
		}
	}
	fclose (fp);

	// Convert port to int
	port = atoi (port_str);

	// Connect to AFU server
	printf ("Attempting to connect to %s:%d\n", host, port);
	if (psl_init_afu_event (status.event, host, port) != PSL_SUCCESS) {
		fflush (stdout);
		fprintf (stderr, "Unable to connect to %s:%d\n", host, port);
		fflush (stderr);
		free (status.event);
		free (afu);
		errno = ENODEV;
		return NULL;
	}

	// Start PSL thread
	status.psl_state = PSL_INIT;
	status.event_list = NULL;
	status.credits = MAX_CREDITS;
	memset(status.active_tags, 0, sizeof(status.active_tags));
	memset(status.buffer_req, 0, sizeof(status.buffer_req));
	status.buffer_read = NULL;
	afu->id = afu_id;
	afu->mmio_size = 0;
	afu->attached = 0;
	afu->running = 0;
	afu->parity_enable= 0;
	afu->catastrophic = 0;
	pthread_create(&(afu->thread), NULL, psl, (void *) afu);
	psl_aux1_change (status.event, status.credits);

	// Reset AFU
	status.cmd.code = PSL_JOB_RESET;
	status.cmd.addr = 0;
	status.cmd.request = AFU_REQUEST;

	wait_with_timeout(status.cmd.request != AFU_IDLE, 10,
			  "waiting for the AFU to go IDLE");

	// Read AFU descriptor
	status.mmio.rnw = 1;
	status.mmio.dw = 1;
	status.mmio.desc = 1;

	// Offset 0x00
	status.mmio.addr = 0;
	status.mmio.request = AFU_REQUEST;

	wait_with_timeout(status.mmio.request != AFU_IDLE, 10,
			  "waiting for the MMIO request to go IDLE");

	value = status.mmio.data;
	afu->desc.req_prog_model = (uint16_t) (value & 0xffffl);
        value >>= 16;
	afu->desc.num_of_afu_CRs = value & 0xffff;
        value >>= 16;
	afu->desc.num_of_processes = value & 0xffff;
        value >>= 16;
	afu->desc.num_ints_per_process = value & 0xffff;

	// Offset 0x20
	status.mmio.addr = 8;
	status.mmio.request = AFU_REQUEST;
	wait_with_timeout(status.mmio.request != AFU_IDLE, 10,
			  "waiting for the MMIO request to go IDLE");
	afu->desc.AFU_CR_len = status.mmio.data;

	// Offset 0x28
	status.mmio.addr = 10;
	status.mmio.request = AFU_REQUEST;
	wait_with_timeout(status.mmio.request != AFU_IDLE, 10,
			  "waiting for the MMIO request to go IDLE");
	afu->desc.AFU_CR_offset = status.mmio.data;

	// Offset 0x30
	status.mmio.addr = 12;
	status.mmio.request = AFU_REQUEST;
	wait_with_timeout(status.mmio.request != AFU_IDLE, 10,
			  "waiting for the MMIO request to go IDLE");
	afu->desc.PerProcessPSA = status.mmio.data;

	// Offset 0x38
	status.mmio.addr = 14;
	status.mmio.request = AFU_REQUEST;
	wait_with_timeout(status.mmio.request != AFU_IDLE, 10,
			  "waiting for the MMIO request to go IDLE");
	afu->desc.PerProcessPSA_offset = status.mmio.data;

	// Offset 0x40
	status.mmio.addr = 16;
	status.mmio.request = AFU_REQUEST;
	wait_with_timeout(status.mmio.request != AFU_IDLE, 10,
			  "waiting for the MMIO request to go IDLE");
	afu->desc.AFU_EB_len = status.mmio.data;

	// Offset 0x48
	status.mmio.addr = 18;
	status.mmio.request = AFU_REQUEST;
	wait_with_timeout(status.mmio.request != AFU_IDLE, 10,
			  "waiting for the MMIO request to go IDLE");
	afu->desc.AFU_EB_offset = status.mmio.data;

	status.mmio.desc = 0;

	// Verify num_of_processes
	if (!afu->desc.num_of_processes) {
		fflush (stdout);
		fprintf (stderr, "ERROR: ");
		fprintf (stderr, "AFU descriptor num_of_processes=0!\n");
		fflush (stderr);
		free (afu);
		errno = ENODEV;
		return NULL;
	}

	// Verify req_prog_model
	if (afu->desc.req_prog_model != 0x0010l) {
		fflush (stdout);
		fprintf (stderr, "ERROR: ");
		fprintf (stderr, "AFU descriptor contains unsupported");
		fprintf (stderr, " req_prog_model value 0x%04x!\n", afu->desc.req_prog_model);
		fflush (stderr);
		free (afu);
		errno = ENODEV;
		return NULL;
	}

	// Minimum interrupts is 1
	status.max_ints = afu->desc.num_ints_per_process;
	if (!status.max_ints)
		status.max_ints = 1;

	return afu;
}

int cxl_afu_attach(struct cxl_afu_h *afu, __u64 wed) {

	if (afu->attached) {
		errno = EINVAL;
		return -1;
	}

	wait_with_timeout(status.cmd.request != AFU_IDLE, 10,
			  "waiting for the AFU to go IDLE");

	// Start AFU
	status.cmd.code = PSL_JOB_START;
	status.cmd.addr = wed;
	status.cmd.request = AFU_REQUEST;
	wait_with_timeout(status.cmd.request == AFU_REQUEST, 10,
			  "waiting for the AFU to start");

	// Wait for job_running
	wait_with_timeout(!afu->running, 10,
			  "waiting for the AFU to start");

	afu->attached = 1;
	return 0;
}

void cxl_afu_free(struct cxl_afu_h *afu) {
	// Check for valid AFU
	if (!afu) return;

	// Wait for job_done
	wait_with_timeout(afu->running, 2, "waiting for the AFU to stop");

	// Reset AFU
	status.cmd.code = PSL_JOB_RESET;
	status.cmd.addr = 0;
	status.cmd.request = AFU_REQUEST;

	// Wait for job_done
	wait_with_timeout(status.cmd.request != AFU_IDLE, 2,
			  "waiting for the AFU to stop");

	// Stop PSL thread
	status.psl_state = PSL_DONE;
	pthread_join(afu->thread, NULL);

	// Shut down socket connection
	psl_close_afu_event (status.event);

	// Free memory
	free (afu);
}

bool cxl_pending_event(struct cxl_afu_h *afu) {
	if (status.event_list)
		return true;
	return false;
}

int cxl_read_event(struct cxl_afu_h *afu, struct cxl_event *event) {
	volatile struct cxl_event_wrapper *head;

	if (!event)
		return -1;

	while (!(status.event_list))
		short_delay();

	head = status.event_list;
	memcpy (event, head->event, head->event->header.size);
	status.event_list = head->_next;
	free ((void *) head->event);
	free ((void *) head);
	return 0;
}

int cxl_mmio_map(struct cxl_afu_h *afu, __u32 flags) {

	if (flags & ~(CXL_MMIO_FLAGS_FULL))
		goto err;
	if (!afu->running) {
		fflush (stdout);
		fprintf (stderr, "ERROR: ");
		fprintf (stderr, "cxl_mmio_map: Must attach AFU first!\n");
		fflush (stderr);
		goto err;
	}
	
	if (!(afu->desc.PerProcessPSA & 0x0100000000000000L)) {
		fflush (stdout);
		fprintf (stderr, "ERROR: ");
		fprintf (stderr, "cxl_mmio_map: AFU descriptor ");
		fprintf (stderr, "Problem State Area Required is not set\n");
		fflush (stderr);
		goto err;
	}

	afu->mmio_flags = flags;
	// Dedicated Process AFU
	if (afu->desc.req_prog_model && 0x0010l)
		afu->mmio_size = 0x4000000; // 64MB, AFU Maximum
	// Only dedicated mode supported for now
	else
		goto err;

	return 0;
err:
	errno = ENODEV;
	return -1;
}

int cxl_mmio_unmap(struct cxl_afu_h *afu) {
	afu->mmio_size = 0;

	return 0;
}

void *cxl_mmio_ptr(struct cxl_afu_h *afu) {
	fflush (stdout);
	fprintf(stderr, "cxl_mmio_ptr:PSLSE does not support direct access");
	fprintf(stderr, " to MMIO address space!\n");
	fflush (stderr);
	return NULL;
}

int cxl_mmio_write64(struct cxl_afu_h *afu, uint64_t offset, uint64_t data) {
	if (afu->catastrophic || (offset >= afu->mmio_size) || (offset & 0x7)) {
		errno = EADDRNOTAVAIL;
		return -1;
	}

	if (!afu->running) {
		fflush (stdout);
		fprintf (stderr, "ERROR: MMIO write without jrunning=1\n");
		fflush (stderr);
		errno = EADDRNOTAVAIL;
		return -1;
	}

	DPRINTF("Sending MMIO write double word to AFU\n");
	status.mmio.rnw = 0;
	status.mmio.dw = 1;
	status.mmio.addr = offset >> 2;
	status.mmio.data = data;
	status.mmio.request = AFU_REQUEST;
	DPRINTF("Waiting for MMIO ack from AFU\n");
	// FIXME: Add timeout
	while (status.mmio.request != AFU_IDLE) short_delay();
	DPRINTF("MMIO write complete\n");
	return 0;
}

int cxl_mmio_read64(struct cxl_afu_h *afu, uint64_t offset, uint64_t *data) {
	if (afu->catastrophic || (offset >= afu->mmio_size) || (offset & 0x7)) {
		errno = EADDRNOTAVAIL;
		return -1;
	}

	if (!afu->running) {
		fflush (stdout);
		fprintf (stderr, "ERROR: MMIO read without jrunning=1\n");
		fflush (stderr);
		errno = EADDRNOTAVAIL;
		*data = 0xfeedb00ffeedb00fl;
		return -1;
	}

	DPRINTF("Sending MMIO read double word to AFU\n");
	status.mmio.rnw = 1;
	status.mmio.dw = 1;
	status.mmio.addr = offset >> 2;
	status.mmio.request = AFU_REQUEST;
	DPRINTF("Waiting for MMIO ack from AFU\n");
	// FIXME: Add timeout
	while (status.mmio.request != AFU_IDLE) short_delay();
	*data = status.mmio.data;
	DPRINTF("MMIO read complete\n");
	return 0;
}

int cxl_mmio_write32(struct cxl_afu_h *afu, uint64_t offset, uint32_t data) {
	uint64_t value;

	if (afu->catastrophic || (offset >= afu->mmio_size) || (offset & 0x3)) {
		errno = EADDRNOTAVAIL;
		return -1;
	}

	if (!afu->running) {
		fflush (stdout);
		fprintf (stderr, "ERROR: MMIO write without jrunning=1\n");
		fflush (stderr);
		errno = EADDRNOTAVAIL;
		return -1;
	}

	value = data;
	value <<= 32;
	value |= data;
	DPRINTF("Sending MMIO write single word to AFU\n");
	status.mmio.rnw = 0;
	status.mmio.dw = 0;
	status.mmio.addr = offset >> 2;
	status.mmio.data = value;
	status.mmio.request = AFU_REQUEST;
	DPRINTF("Waiting for MMIO ack from AFU\n");
	// FIXME: Add timeout
	while (status.mmio.request != AFU_IDLE) short_delay();
	DPRINTF("MMIO write complete\n");
	return 0;
}

int cxl_mmio_read32(struct cxl_afu_h *afu, uint64_t offset, uint32_t *data) {
	if (afu->catastrophic || (offset >= afu->mmio_size) || (offset & 0x3)) {
		errno = EADDRNOTAVAIL;
		return -1;
	}

	if (!afu->running) {
		fflush (stdout);
		fprintf (stderr, "ERROR: MMIO read without jrunning=1\n");
		fflush (stderr);
		errno = EADDRNOTAVAIL;
		*data = 0xfeedb00fl;
		return -1;
	}

	DPRINTF("Sending MMIO read single word to AFU\n");
	status.mmio.rnw = 1;
	status.mmio.dw = 0;
	status.mmio.addr = offset >> 2;
	status.mmio.request = AFU_REQUEST;
	DPRINTF("Waiting for MMIO ack from AFU\n");
	// FIXME: Add timeout
	while (status.mmio.request != AFU_IDLE) short_delay();
	*data = (uint32_t) status.mmio.data;

	DPRINTF("MMIO read complete\n");
	return 0;
}
