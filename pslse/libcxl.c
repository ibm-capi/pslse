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

#include "libcxl.h"
#include "libcxl_internal.h"
#include "psl_interface/psl_interface.h"

#define ODD_PARITY 1		// 1=Odd parity, 0=Even parity

#define PAGED_RANDOMIZER 0	// Setting to smaller values means more
				// frequent paged responses.
				// 0 disables all paged responses.
				// 1 is an illegal value as every response
				// would be paged.

#define RESP_RANDOMIZER 10	// Setting to 1 achieves fastest responses,
				// Large values increase response delays
				// Zero is an illegal value

// System constants
#define MAX_LINE_CHARS 1024
#define CACHELINE_BYTES 128
#define DWORDS_PER_CACHELINE 16
#define BYTES_PER_DWORD 8
#define WORD_OFFSET 4

struct afu_command {
	int request;
	uint32_t code;
	uint64_t addr;
};

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
struct afu_mmio {
	int request;
	int rnw;
	uint32_t dw;
	uint32_t addr;
	uint64_t data;
	uint32_t parity;
	uint32_t desc;
};

struct afu_br {
	uint32_t tag;
	uint32_t size;
	uint8_t *addr;
	uint8_t resp_type;
	struct afu_br *_next;
};

struct afu_resp {
	uint32_t tag;
	uint32_t code;
	struct afu_resp *_next;
};

struct psl_status {
	struct AFU_EVENT *event;
	volatile int event_occurred;	/* Job done or interrupt */
	volatile unsigned int credits;
	volatile struct afu_command cmd;
	volatile struct afu_mmio mmio;
	volatile int psl_state;
	struct afu_br *first_br;
	struct afu_br *last_br;
	struct afu_resp *first_resp;
	struct afu_resp *last_resp;
};

static struct psl_status status;

static void short_delay() {
	struct timespec ts;
	ts.tv_sec = 0;
	ts.tv_nsec = 4;	// 250MHz = 4ns cycle time
	nanosleep (&ts, &ts);
}

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

static void generate_cl_parity(uint8_t *data, uint8_t *parity) {
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
		struct afu_resp *temp;
		temp = status.first_resp;
		status.first_resp = status.first_resp->_next;
		if (status.first_resp == NULL) {
			status.last_resp = NULL;
		}
		free (temp);
	}
}

static void buffer_event (int rnw, uint32_t tag, uint8_t *addr) {
	uint8_t par[DWORDS_PER_CACHELINE/8];

	if (status.psl_state==PSL_FLUSHING) {
#ifdef DEBUG
		printf ("Response FLUSHED tag=0x%02x\n", tag);
#endif /* #ifdef DEBUG */
		add_resp (tag, PSL_RESPONSE_FLUSHED);
		return;
	}

	if (!testmemaddr (addr)) {
		fflush (stdout);
		fprintf (stderr, "AFU attempted ");
		if (rnw)
			fprintf (stderr, "write");
		else
			fprintf (stderr, "read");
		fprintf (stderr, " to invalid address 0x");
		fprintf (stderr, "%016llx", (long long) addr);
		fprintf (stderr, "\n");
		fflush (stderr);
#ifdef DEBUG
		printf ("Response AERROR tag=0x%02x\n", tag);
#endif /* #ifdef DEBUG */
		add_resp (tag, PSL_RESPONSE_AERROR);
		status.psl_state = PSL_FLUSHING;
		return;
	}

	if (rnw) {
#ifdef DEBUG
		printf ("Buffer Read tag=0x%02x\n", tag);
#endif /* #ifdef DEBUG */
		psl_buffer_read (status.event, tag, (uint64_t) addr,
				 CACHELINE_BYTES);
	}
	else {
#ifdef DEBUG
		printf ("Buffer Write tag=0x%02x\n", tag);
#endif /* #ifdef DEBUG */
		generate_cl_parity(addr, par);
		psl_buffer_write (status.event, tag, (uint64_t) addr,
				  CACHELINE_BYTES,
				  addr, par);
		++status.credits;
#ifdef DEBUG
		printf ("Response tag=0x%02x\n", tag);
#endif /* #ifdef DEBUG */
		if (status.psl_state==PSL_NLOCK) {
#ifdef DEBUG
			printf ("Nlock response for read, tag=0x%02x\n", tag);
			fflush (stdout);
#endif /* #ifdef DEBUG */
			add_resp (tag, PSL_RESPONSE_NLOCK);
		}
		else if (!PAGED_RANDOMIZER || (rand() % PAGED_RANDOMIZER)) {
			// Inject random "Paged" response
			add_resp (tag, PSL_RESPONSE_DONE);
		}
		else {
			add_resp (tag, PSL_RESPONSE_PAGED);
			status.psl_state = PSL_FLUSHING;
		}
	}
}

static void add_buffer_read (uint32_t tag, uint32_t size, uint8_t *addr,
			     uint8_t resp_type) {
	struct afu_br *temp;

	temp = (struct afu_br *) malloc (sizeof (struct afu_br));
	temp->tag = tag;
	temp->size = size;
	temp->addr = addr;
	temp->resp_type = resp_type;
	temp->_next = NULL;

	// List is empty
	if (status.last_br == NULL) {
		status.first_br = temp;
		status.last_br = temp;
		return;
	}

	// Append to list
	status.last_br->_next = temp;
	status.last_br = temp;
}

static void remove_buffer_read () {
	struct afu_br *temp;
	
	if (status.first_br == status.last_br)
		status.last_br = NULL;
	temp = status.first_br;
	status.first_br = status.first_br->_next;
	free (temp);

	// Issue buffer read for pending writes
	if (status.first_br) {
		buffer_event (1, status.first_br->tag, status.first_br->addr);
	}
}

static void handle_aux2_change (struct cxl_afu_h* afu) {
	status.event->aux2_change = 0;
	if (afu->running != status.event->job_running) {
		status.event_occurred = 1-status.event->job_running;
	}
	if (status.event->job_running)
		afu->running = 1;
	if (status.event->job_done) {
		if (status.cmd.request==AFU_RESET)
			status.cmd.request = AFU_IDLE;
		afu->running = 0;
	}
	if (status.event->parity_enable)
		afu->parity_enable = 1;

#ifdef DEBUG
	printf ("AUX2 jrunning=%d jdone=%d", status.event->job_running,
		status.event->job_done);
	if (status.event->job_done) {
		printf (" jerror=0x%016llx",
			(long long) status.event->job_error);
	}
	printf ("\n");
#endif /* #ifdef DEBUG */
}

static void handle_mmio_acknowledge (struct cxl_afu_h* afu) {
#ifdef DEBUG
	printf ("MMIO Acknowledge\n");
#endif /* #ifdef DEBUG */
	status.mmio.request = AFU_IDLE;
	if (afu->parity_enable && status.event->mmio_read &&
	     (status.mmio.parity !=
	      generate_parity(status.mmio.data, ODD_PARITY))) {
		fflush (stdout);
		fprintf (stderr, "ERROR:Parity error");
		fprintf (stderr, " on MMIO read data\n");
		fprintf (stderr, " Data:0x%016llx\n",
			 (long long) status.mmio.data);
		fprintf (stderr, " Parity:%d\n", status.mmio.parity);
		fflush (stderr);
		status.mmio.data = ~0ull;
	}
}

static void handle_buffer_read (struct cxl_afu_h* afu) {
	uint64_t offset;
	uint32_t tag;
	uint8_t *buffer;
	uint8_t parity[DWORDS_PER_CACHELINE/8];
	uint8_t parity_check[DWORDS_PER_CACHELINE/8];
	unsigned i;

	tag = status.first_br->tag;
	buffer = (uint8_t *) malloc (CACHELINE_BYTES);
	if (psl_get_buffer_read_data (status.event, buffer, parity)
	    == PSL_SUCCESS) {
		offset = (uint64_t) status.first_br->addr;
		offset &= 0x7Fll;
		memcpy (status.first_br->addr, &(buffer[offset]),
			status.first_br->size);
		++status.credits;
		if ((status.first_br->resp_type==RESP_UNLOCK) &&
		    ((status.psl_state==PSL_LOCK) ||
	             (status.psl_state==PSL_NLOCK))) {
#ifdef DEBUG
			printf ("Lock sequence completed\n");
			fflush (stdout);
#endif /* #ifdef DEBUG */
			status.psl_state = PSL_RUNNING;
		}
#ifdef DEBUG
		printf ("Response tag=0x%02x\n", tag);
#endif /* #ifdef DEBUG */
		generate_cl_parity(buffer, parity_check);
		if (afu->parity_enable &&
		    memcmp(parity, parity_check, sizeof(parity))) {
			fflush (stdout);
			fprintf (stderr, "ERROR:Parity error on ");
			fprintf (stderr, "buffer read data tag=0x");
			fprintf (stderr, "%02x\n", tag);
			for (i=0; i<CACHELINE_BYTES; i++) {
				if (!(i%32))
					fprintf (stderr, "\n  0x");
				fprintf (stderr, "%02x", buffer[i]);
			}
			fprintf (stderr, "\n");
			fflush (stderr);
			add_resp (tag, PSL_RESPONSE_DERROR);
			status.psl_state = PSL_FLUSHING;
		}
		else if (!PAGED_RANDOMIZER ||
			 (rand() % PAGED_RANDOMIZER)) {
			// Inject random "Paged" response
			add_resp (tag, PSL_RESPONSE_DONE);
		}
		else {
			add_resp (tag, PSL_RESPONSE_PAGED);
			status.psl_state = PSL_FLUSHING;
		}
		// Stop remembing status.first_br
		remove_buffer_read();
	}
}

static int error_check (struct cxl_afu_h* afu) {
	unsigned fail;
	uint32_t tag, tagpar, size, cmd, cmdpar;
	uint64_t addr;
	uint64_t addrpar;
	uint8_t *addrptr;

	status.event->command_valid = 0;
	tag = status.event->command_tag;
	tagpar = status.event->command_tag_parity;
	size = status.event->command_size;
	cmd = status.event->command_code;
	cmdpar = status.event->command_code_parity;
	addr = status.event->command_address;
	addrptr = (uint8_t *) status.event->command_address;
	addrpar = status.event->command_address_parity;

	if (!afu->running) {
		fflush (stdout);
		fprintf (stderr, "ERROR:Command without jrunning=1,");
		fprintf (stderr, " tag=0x%02x\n", tag);
		fflush (stderr);
	}

	if (afu->parity_enable) {
		fail = 0;
		fflush (stdout);
		if (addrpar != generate_parity(addr, ODD_PARITY)) {
			fflush (stdout);
			fprintf (stderr, "ERROR:Parity error on command");
			fprintf (stderr, " address=0x%016llx\n",
				 (long long) addr);
			fflush (stderr);
			fail = 1;
		}
		if (tagpar != generate_parity(tag, ODD_PARITY)) {
			fflush (stdout);
			fprintf (stderr, "ERROR:Parity error on command");
			fprintf (stderr, " tag=0x%02x\n", tag);
			fflush (stderr);
			fail = 1;
		}
		if (cmdpar != generate_parity(cmd, ODD_PARITY)) {
			fflush (stdout);
			fprintf (stderr, "ERROR:Parity error on command");
			fprintf (stderr, " code=0x%04x\n", cmd);
			fflush (stderr);
			fail = 1;
		}
		if (fail) {
#ifdef DEBUG
			printf ("Response FAILED")
			printf (" tag=0x%02x\n", tag);
#endif /* #ifdef DEBUG */
			add_resp (tag, PSL_RESPONSE_FAILED);
			return 1;
		}
	}

	return 0;
}

static void handle_command_valid (struct cxl_afu_h* afu) {
	uint32_t tag, tagpar, size, cmd, cmdpar;
	uint64_t addr;
	uint64_t addrpar;
	uint8_t *addrptr;
	uint8_t resp_type;

	status.event->command_valid = 0;
	tag = status.event->command_tag;
	tagpar = status.event->command_tag_parity;
	size = status.event->command_size;
	cmd = status.event->command_code;
	cmdpar = status.event->command_code_parity;
	addr = status.event->command_address;
	addrptr = (uint8_t *) status.event->command_address;
	addrpar = status.event->command_address_parity;

#ifdef DEBUG
	printf ("Command tag=0x%02x\n", status.event->command_tag);
#endif /* #ifdef DEBUG */

	if (error_check (afu))
		return;

	if ((status.psl_state==PSL_FLUSHING) && (cmd != 1)) {
#ifdef DEBUG
		printf ("Response FLUSHED tag=0x%02x\n", tag);
		fflush (stdout);
#endif /* #ifdef DEBUG */
		add_resp (tag, PSL_RESPONSE_FLUSHED);
		return;
	}
	--status.credits;

	if (((status.psl_state==PSL_LOCK) &&
	     (cmd !=PSL_COMMAND_WRITE_UNLOCK)) ||
	    (status.psl_state==PSL_NLOCK)) {
#ifdef DEBUG
		printf ("Response NLOCK tag=0x%02x\n", tag);
#endif /* #ifdef DEBUG */
		add_resp (tag, PSL_RESPONSE_NLOCK);
		status.psl_state=PSL_NLOCK;
		update_pending_resps (PSL_RESPONSE_NLOCK);
#ifdef DEBUG
		printf ("Dumping lock intervening command, tag=0x%02x\n", tag);
		fflush (stdout);
#endif /* #ifdef DEBUG */
		return;
	}

	resp_type = RESP_NORMAL;
	switch (cmd) {
	// Interrupt
	case PSL_COMMAND_INTREQ:
		printf ("AFU interrupt command received\n");
		status.event_occurred = 1;
#ifdef DEBUG
		printf ("Response tag=0x%02x\n", tag);
#endif /* #ifdef DEBUG */
		add_resp (tag, PSL_RESPONSE_FLUSHED);
		break;
	// Restart
	case PSL_COMMAND_RESTART:
		status.psl_state = PSL_RUNNING;
#ifdef DEBUG
		printf ("AFU restart command received\n");
		printf ("Response tag=0x%02x\n", tag);
#endif /* #ifdef DEBUG */
		add_resp (tag, PSL_RESPONSE_DONE);
		break;
	case PSL_COMMAND_LOCK:
		update_pending_resps (PSL_RESPONSE_NLOCK);
		status.psl_state = PSL_LOCK;
#ifdef DEBUG
		printf ("Starting lock sequence, tag=0x%02x\n", tag);
		fflush (stdout);
#endif /* #ifdef DEBUG */
		break;
	case PSL_COMMAND_UNLOCK:
		resp_type = RESP_UNLOCK;
		break;
	// Memory Reads
	case PSL_COMMAND_READ_CL_LCK:
		update_pending_resps (PSL_RESPONSE_NLOCK);
		status.psl_state = PSL_LOCK;
#ifdef DEBUG
		printf ("Starting lock sequence, tag=0x%02x\n", tag);
		fflush (stdout);
#endif /* #ifdef DEBUG */
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
#ifdef DEBUG
		printf ("Read command size=%d tag=0x%02x\n", size, tag);
#endif /* #ifdef DEBUG */
		buffer_event (0, tag, addrptr);
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
#ifdef DEBUG
		printf ("Write command size=%d, tag=0x%02x\n", size,
			tag);
#endif /* #ifdef DEBUG */
		// Only issue buffer read if no other pending
		if (!status.first_br) {
			buffer_event (1, tag, addrptr);
		}
		// Remember tag and addr
		add_buffer_read (tag, size, addrptr, resp_type);
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
		fprintf (stderr, "ERROR:Command currently unsupported");
		fprintf (stderr, " 0x%04x\n", cmd);
		fflush (stderr);
		break;
	}
}

static void handle_psl_events (struct cxl_afu_h* afu) {
	if (status.event->aux2_change)
		handle_aux2_change (afu);

	if (psl_get_mmio_acknowledge (status.event, (uint64_t *)
	    &(status.mmio.data), (uint32_t *) &(status.mmio.parity)) ==
	    PSL_SUCCESS)
		handle_mmio_acknowledge (afu);

	if (status.first_br && status.psl_state==PSL_FLUSHING)
		remove_buffer_read();
	else if (status.first_br)
		handle_buffer_read (afu);

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
#ifdef DEBUG
				printf ("Job 0x%02x\n", status.cmd.code);
#endif /* #ifdef DEBUG */
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
#ifdef DEBUG
					printf ("MMIO Read %d\n",
						status.mmio.addr);
#endif /* #ifdef DEBUG */
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
#ifdef DEBUG
					printf ("MMIO Write %d\n",
						status.mmio.addr);
#endif /* #ifdef DEBUG */
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
	}

	pthread_exit(NULL);
}

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
			printf ("Invalid format in shim_host.dat.  Expected ',' :%s\n",
				hostdata);
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
			printf ("Invalid format in shim_host.dat.  Expected ':' :%s\n",
				hostdata);
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
		printf ("Unable to connect to %s:%d\n", host, port);
		free (status.event);
		free (afu);
		errno = ENODEV;
		return NULL;
	}

	// Start PSL thread
	status.psl_state = PSL_INIT;
	status.event_occurred = 0;
	status.credits = 64;
	status.first_br = NULL;
	status.last_br = NULL;
	afu->id = afu_id;
	afu->mmio_size = 0;
	afu->attached = 0;
	afu->running = 0;
	afu->parity_enable= 0;
	pthread_create(&(afu->thread), NULL, psl, (void *) afu);

	psl_aux1_change (status.event, status.credits);

	// Reset AFU
	status.cmd.code = PSL_JOB_RESET;
	status.cmd.addr = 0;
	status.cmd.request = AFU_REQUEST;
	// FIXME: Add timeout
	while (status.cmd.request != AFU_IDLE) short_delay();

	// Read AFU descriptor
	status.mmio.rnw = 1;
	status.mmio.dw = 1;
	status.mmio.desc = 1;

	// Offset 0x00
	status.mmio.addr = 0;
	status.mmio.request = AFU_REQUEST;
	// FIXME: Add timeout
	while (status.mmio.request != AFU_IDLE) short_delay();
	value = be64toh(status.mmio.data);
	afu->desc.req_prog_model = value && 0xffff;
        value >>= 16;
	afu->desc.num_of_afu_CRs = value && 0xffff;
        value >>= 16;
	afu->desc.num_of_processes = value && 0xffff;
        value >>= 16;
	afu->desc.num_ints_per_process = value && 0xffff;

	// Offset 0x20
	status.mmio.addr = 8;
	status.mmio.request = AFU_REQUEST;
	// FIXME: Add timeout
	while (status.mmio.request != AFU_IDLE) short_delay();
	afu->desc.AFU_CR_len = be64toh(status.mmio.data);

	// Offset 0x28
	status.mmio.addr = 10;
	status.mmio.request = AFU_REQUEST;
	// FIXME: Add timeout
	while (status.mmio.request != AFU_IDLE) short_delay();
	afu->desc.AFU_CR_offset = be64toh(status.mmio.data);

	// Offset 0x30
	status.mmio.addr = 12;
	status.mmio.request = AFU_REQUEST;
	// FIXME: Add timeout
	while (status.mmio.request != AFU_IDLE) short_delay();
	afu->desc.PerProcessPSA = be64toh(status.mmio.data);

	// Offset 0x38
	status.mmio.addr = 14;
	status.mmio.request = AFU_REQUEST;
	// FIXME: Add timeout
	while (status.mmio.request != AFU_IDLE) short_delay();
	afu->desc.PerProcessPSA_offset = be64toh(status.mmio.data);

	// Offset 0x40
	status.mmio.addr = 16;
	status.mmio.request = AFU_REQUEST;
	// FIXME: Add timeout
	while (status.mmio.request != AFU_IDLE) short_delay();
	afu->desc.AFU_EB_len = be64toh(status.mmio.data);

	// Offset 0x48
	status.mmio.addr = 18;
	status.mmio.request = AFU_REQUEST;
	// FIXME: Add timeout
	while (status.mmio.request != AFU_IDLE) short_delay();
	afu->desc.AFU_EB_offset = be64toh(status.mmio.data);

	status.mmio.desc = 0;

	return afu;
}

int cxl_afu_attach(struct cxl_afu_h *afu, __u64 wed) {

	if (afu->attached) {
		errno = EINVAL;
		return -1;
	}

	// FIXME: Add timeout
	while (status.cmd.request != AFU_IDLE) short_delay();

	// Start AFU
	status.cmd.code = PSL_JOB_START;
	status.cmd.addr = wed;
	status.cmd.request = AFU_REQUEST;
	// FIXME: Add timeout
	while (status.cmd.request == AFU_REQUEST) short_delay();

	// Wait for job_running
	while (!afu->running) {
		// FIXME: Timeout
		short_delay();
	}

	afu->attached = 1;
	return 0;
}

void cxl_afu_free(struct cxl_afu_h *afu) {
	// Check for valid AFU
	if (!afu) return;

	// Wait for job_done
	while (afu->running) {
		// FIXME: Timeout
		short_delay();
	}

	// Reset AFU
	status.cmd.code = PSL_JOB_RESET;
	status.cmd.addr = 0;
	status.cmd.request = AFU_REQUEST;

	// Wait for job_done
	while (status.cmd.request != AFU_IDLE) {
		// FIXME: Timeout
		short_delay();
	}

	// Stop PSL thread
	status.psl_state = PSL_DONE;
	pthread_join(afu->thread, NULL);

	// Shut down socket connection
	psl_close_afu_event (status.event);

	// Free memory
	free (afu);
}

int cxl_mmio_map(struct cxl_afu_h *afu, __u32 flags) {

	if (flags & ~(CXL_MMIO_FLAGS_FULL))
		goto err;
	if (!afu->running) {
		fflush (stdout);
		fprintf (stderr, "ERROR:cxl_mmio_map:Must attach AFU first!\n");
		fflush (stderr);
		goto err;
	}

	afu->mmio_flags = flags;
	// Dedicated Process AFU
	if (afu->desc.req_prog_model && 0x0010)
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
	if ((offset >= afu->mmio_size) || (offset & 0x7)) {
		errno = EADDRNOTAVAIL;
		return -1;
	}

	if (!afu->running) {
		fflush (stdout);
		fprintf (stderr, "ERROR:MMIO write without jrunning=1\n");
		fflush (stderr);
		errno = EADDRNOTAVAIL;
		return -1;
	}

#ifdef DEBUG
	printf ("Sending MMIO write double word to AFU\n");
#endif /* #ifdef DEBUG */
	status.mmio.rnw = 0;
	status.mmio.dw = 1;
	status.mmio.addr = offset >> 2;
	status.mmio.data = data;
	status.mmio.request = AFU_REQUEST;
#ifdef DEBUG
	printf ("Waiting for MMIO ack from AFU\n");
#endif /* #ifdef DEBUG */
	// FIXME: Add timeout
	while (status.mmio.request != AFU_IDLE) short_delay();
#ifdef DEBUG
	printf ("MMIO write complete\n");
#endif /* #ifdef DEBUG */
	return 0;
}

int cxl_mmio_read64(struct cxl_afu_h *afu, uint64_t offset, uint64_t *data) {
	if ((offset >= afu->mmio_size) || (offset & 0x7)) {
		errno = EADDRNOTAVAIL;
		return -1;
	}

	if (!afu->running) {
		fflush (stdout);
		fprintf (stderr, "ERROR:MMIO read without jrunning=1\n");
		fflush (stderr);
		errno = EADDRNOTAVAIL;
		*data = 0xfeedb00ffeedb00fl;
		return -1;
	}

#ifdef DEBUG
	printf ("Sending MMIO read double word to AFU\n");
#endif /* #ifdef DEBUG */
	status.mmio.rnw = 1;
	status.mmio.dw = 1;
	status.mmio.addr = offset >> 2;
	status.mmio.request = AFU_REQUEST;
#ifdef DEBUG
	printf ("Waiting for MMIO ack from AFU\n");
#endif /* #ifdef DEBUG */
	// FIXME: Add timeout
	while (status.mmio.request != AFU_IDLE) short_delay();
	*data = status.mmio.data;
#ifdef DEBUG
	printf ("MMIO read complete\n");
#endif /* #ifdef DEBUG */
	return 0;
}

int cxl_mmio_write32(struct cxl_afu_h *afu, uint64_t offset, uint32_t data) {
	uint64_t value;

	if ((offset >= afu->mmio_size) || (offset & 0x3)) {
		errno = EADDRNOTAVAIL;
		return -1;
	}

	if (!afu->running) {
		fflush (stdout);
		fprintf (stderr, "ERROR:MMIO write without jrunning=1\n");
		fflush (stderr);
		errno = EADDRNOTAVAIL;
		return -1;
	}

	value = data;
	value <<= 32;
	value |= data;
#ifdef DEBUG
	printf ("Sending MMIO write single word to AFU\n");
#endif /* #ifdef DEBUG */
	status.mmio.rnw = 0;
	status.mmio.dw = 0;
	status.mmio.addr = offset >> 2;
	status.mmio.data = value;
	status.mmio.request = AFU_REQUEST;
#ifdef DEBUG
	printf ("Waiting for MMIO ack from AFU\n");
#endif /* #ifdef DEBUG */
	// FIXME: Add timeout
	while (status.mmio.request != AFU_IDLE) short_delay();
#ifdef DEBUG
	printf ("MMIO write complete\n");
#endif /* #ifdef DEBUG */
	return 0;
}

int cxl_mmio_read32(struct cxl_afu_h *afu, uint64_t offset, uint32_t *data) {
	if ((offset >= afu->mmio_size) || (offset & 0x3)) {
		errno = EADDRNOTAVAIL;
		return -1;
	}

	if (!afu->running) {
		fflush (stdout);
		fprintf (stderr, "ERROR:MMIO read without jrunning=1\n");
		fflush (stderr);
		errno = EADDRNOTAVAIL;
		*data = 0xfeedb00fl;
		return -1;
	}

#ifdef DEBUG
	printf ("Sending MMIO read single word to AFU\n");
#endif /* #ifdef DEBUG */
	status.mmio.rnw = 1;
	status.mmio.dw = 0;
	status.mmio.addr = offset >> 2;
	status.mmio.request = AFU_REQUEST;
#ifdef DEBUG
	printf ("Waiting for MMIO ack from AFU\n");
#endif /* #ifdef DEBUG */
	// FIXME: Add timeout
	while (status.mmio.request != AFU_IDLE) short_delay();
	*data = (uint32_t) status.mmio.data;
#ifdef DEBUG
	printf ("MMIO read complete\n");
#endif /* #ifdef DEBUG */
	return 0;
}
