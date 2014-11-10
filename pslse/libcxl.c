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
#include <sys/time.h>
#include <time.h>

#include "libcxl.h"
#include "psl_interface/psl_interface.h"

#define MAX_LINE_CHARS 1024
#define CACHELINE_BYTES 128
#define DWORDS_PER_CACHELINE 16
#define BYTES_PER_DWORD 8

#define ODD_PARITY 1		// 1=Odd parity, 0=Even parity

#define PAGED_RANDOMIZER 50	// Setting to smaller values means more
				// frequent paged responses.
				// 0 disables all paged responses.
				// 1 is an illegal value as every response
				// would be paged.

#define RESP_RANDOMIZER 10	// Setting to 1 achieves fastest responses,
				// Large values increase response delays
				// Zero is an illegal value

struct afu_descriptor {
	uint16_t num_ints_per_process;
	uint16_t num_of_processes;
	uint16_t num_of_afu_CRs;
	uint16_t req_prog_model;
	uint64_t reserved1;
	uint64_t reserved2;
	uint64_t reserved3;
	uint64_t AFU_CR_len;
	uint64_t AFU_CR_offset;
	uint64_t PerProcessPSA;
	uint64_t PerProcessPSA_offset;
	uint64_t AFU_EB_len;
	uint64_t AFU_EB_offset;
};

struct cxl_afu_h {
	const char *id;
	pthread_t thread;
	volatile __u32 flags;
	volatile int started;
	volatile size_t mapped;
	volatile struct afu_descriptor desc;
};

struct afu_command {
	int request;
	uint32_t code;
	uint64_t addr;
};

enum PSL_STATE {
	PSL_RUNNING,
	PSL_FLUSHING,
	PSL_DONE
};

enum AFU_STATE {
	AFU_IDLE,
	AFU_RESET,
	AFU_REQUEST,
	AFU_PENDING
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
	while (data) {
		parity = 1-parity;
		data &= data-1;
	}
	return parity;
}

static void generate_cl_parity(uint8_t *data, uint8_t *parity) {
	int i;
	uint64_t dw;
	uint8_t p;

	for (i=0; i<DWORDS_PER_CACHELINE; i++) {
		memcpy(&dw, &(data[BYTES_PER_DWORD*i]), BYTES_PER_DWORD);
		if ((i%BYTES_PER_DWORD)==0)
			parity[i/BYTES_PER_DWORD]=0;
		parity[i/BYTES_PER_DWORD]<<=1;
		p=generate_parity(dw, ODD_PARITY);
		parity[i/BYTES_PER_DWORD]+=p;
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
		if (status.first_resp == NULL)
			status.last_resp = NULL;
		free (temp);
	}
}

static void buffer_event (int rnw, uint32_t tag, uint8_t *addr) {
	uint8_t par[2];

	if (status.psl_state==PSL_FLUSHING) {
#ifdef DEBUG
		printf ("Response FLUSHED tag=0x%02x\n", tag);
#endif /* #ifdef DEBUG */
		add_resp (tag, PSL_RESPONSE_FLUSHED);
		return;
	}

	if (!testmemaddr (addr)) {
		printf ("AFU attempted ");
		if (rnw)
			printf ("read");
		else
			printf ("write");
		printf (" to invalid address 0x%016llx\n",(long long) addr);
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
		// Inject random "Paged" response
		if (!PAGED_RANDOMIZER || (rand() % PAGED_RANDOMIZER)) {
			add_resp (tag, PSL_RESPONSE_DONE);
		}
		else {
			add_resp (tag, PSL_RESPONSE_PAGED);
			status.psl_state = PSL_FLUSHING;
		}
	}
}

static void add_buffer_read (uint32_t tag, uint32_t size, uint8_t *addr) {
	struct afu_br *temp;

	//printf ("Remembering write request 0x%02x\n", tag);
	temp = (struct afu_br *) malloc (sizeof (struct afu_br));
	temp->tag = tag;
	temp->size = size;
	temp->addr = addr;
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
	
	//printf ("Forgeting write request 0x%02x\n", status.first_br->tag);
	if (status.first_br == status.last_br)
		status.last_br = NULL;
	temp = status.first_br;
	status.first_br = status.first_br->_next;
	free (temp);

	// Issue buffer read for pending writes
	if (status.first_br) {
		//printf ("Buffer read request 0x%02x\n", status.first_br->tag);
		buffer_event (1, status.first_br->tag, status.first_br->addr);
	}
}

static void handle_psl_events (struct cxl_afu_h* afu) {
	uint32_t tag, size;
	uint8_t *addr;
	uint8_t parity[DWORDS_PER_CACHELINE];

	if (status.event->aux2_change) {
		status.event->aux2_change = 0;
		if (afu->started != status.event->job_running) {
			status.event_occurred = 1-status.event->job_running;
		}
		if (status.event->job_running)
			afu->started = 1;
		if (status.event->job_done) {
			if (status.cmd.request==AFU_RESET) {
				status.cmd.request = AFU_IDLE;
				afu->started = 0;
			}
			else {
				status.cmd.code = PSL_JOB_RESET;
				status.cmd.addr = 0;
				status.cmd.request = AFU_REQUEST;
			}
		}
#ifdef DEBUG
		printf ("AUX2 jrunning=%d jdone=%d", status.event->job_running,
			status.event->job_done);
		if (status.event->job_done) {
			printf (" jerror=0x%016llx", (long long)
				status.event->job_error);
		}
		printf ("\n");
#endif /* #ifdef DEBUG */
	}
	if (psl_get_mmio_acknowledge (status.event, (uint64_t *)
	    &(status.mmio.data), (uint32_t *) &(status.mmio.parity)) ==
	    PSL_SUCCESS) {
#ifdef DEBUG
		printf ("MMIO Acknowledge\n");
#endif /* #ifdef DEBUG */
		status.mmio.request = AFU_IDLE;
	}
	if (status.first_br && status.psl_state==PSL_FLUSHING) {
		add_resp (status.first_br->tag, PSL_RESPONSE_FLUSHED);
		remove_buffer_read();
	}
	else if (status.first_br) {
		uint8_t *buffer = (uint8_t *) malloc (CACHELINE_BYTES);
		if (psl_get_buffer_read_data (status.event, buffer, parity)
		    == PSL_SUCCESS) {
			uint64_t offset = (uint64_t) status.first_br->addr;
			offset &= 0x7Fll;
			memcpy (status.first_br->addr, &(buffer[offset]),
				status.first_br->size);
			++status.credits;
#ifdef DEBUG
			printf ("Response tag=0x%02x\n", status.first_br->tag);
#endif /* #ifdef DEBUG */
			// Inject random "Paged" response
			if (!PAGED_RANDOMIZER || (rand() % PAGED_RANDOMIZER)) {
				add_resp (status.first_br->tag,
					  PSL_RESPONSE_DONE);
			}
			else {
				add_resp (status.first_br->tag,
					  PSL_RESPONSE_PAGED);
				status.psl_state = PSL_FLUSHING;
			}
			// Stop remembing status.first_br
			remove_buffer_read();
		}
	}
	if (status.event->command_valid) {
#ifdef DEBUG
		printf ("Command tag=0x%02x\n", status.event->command_tag);
#endif /* #ifdef DEBUG */
		status.event->command_valid = 0;
		tag = status.event->command_tag;
		size = status.event->command_size;
		if ((status.psl_state==PSL_FLUSHING) &&
		    (status.event->command_code != 1)) {
#ifdef DEBUG
			printf ("Response FLUSHED tag=0x%02x\n", tag);
			fflush (stdout);
#endif /* #ifdef DEBUG */
			add_resp (tag, PSL_RESPONSE_FLUSHED);
			return;
		}
		--status.credits;
		addr = (uint8_t *) status.event->command_address;
		switch (status.event->command_code) {
		// Interrupt
		case 0x0000:
			printf ("AFU interrupt command received\n");
			status.event_occurred = 1;
#ifdef DEBUG
			printf ("Response tag=0x%02x\n", tag);
#endif /* #ifdef DEBUG */
			add_resp (tag, PSL_RESPONSE_FLUSHED);
			break;
		// Restart
		case 0x0001:
			status.psl_state = PSL_RUNNING;
#ifdef DEBUG
			printf ("AFU restart command received\n");
			printf ("Response tag=0x%02x\n", tag);
#endif /* #ifdef DEBUG */
			add_resp (tag, PSL_RESPONSE_DONE);
			break;
		// Memory Reads
		case 0x0a50:
		case 0x0a60:
		case 0x0a6b:
		case 0x0a67:
		case 0x0a00:
		case 0x0e00:
		case 0x0a90:
		case 0x0aa0:
		case 0x0ad0:
		case 0x0af0:
#ifdef DEBUG
			printf ("Read command size=%d tag=0x%02x\n", size, tag);
#endif /* #ifdef DEBUG */
			buffer_event (0, tag, addr);
			break;
		// Memory Writes
		case 0x0d60:
		case 0x0d70:
		case 0x0d6b:
		case 0x0d67:
		case 0x0d00:
		case 0x0d10:
		case 0x0da0:
#ifdef DEBUG
			printf ("Write command size=%d, tag=0x%02x\n", size,
				tag);
#endif /* #ifdef DEBUG */
			//printf ("Memory write request 0x%02x\n", tag);
			// Only issue buffer read if no other pending
			if (!status.first_br) {
				//printf ("Buffer read request 0x%02x\n", tag);
				buffer_event (1, tag, addr);
			}
			add_buffer_read (tag, size, addr);
			// Remember tag and addr
			break;
		default:
			break;
		}
	}
}


static void *psl(void *ptr) {
	struct cxl_afu_h *afu = (struct cxl_afu_h *)ptr;

	while (status.psl_state != PSL_DONE) {
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
		return NULL;
	}

	// Allocate AFU_EVENT struct
	status.event = (struct AFU_EVENT *) malloc (sizeof (struct AFU_EVENT));
	if (!status.event ) {
		perror ("malloc");
		free (afu);
		return NULL;
	}
	psl_event_reset (status.event);

	// Connect to AFU server
	fp = fopen ("shim_host.dat", "r");
	if (!fp) {
		perror ("fopen shim_host.dat");
		free (status.event);
		free (afu);
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
		return NULL;
	}

	// Start PSL thread
	status.psl_state = PSL_RUNNING;
	status.event_occurred = 0;
	status.credits = 64;
	status.first_br = NULL;
	status.last_br = NULL;
	afu->id = afu_id;
	afu->started = 0;
	afu->mapped = 0;
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

	return afu;
}

int cxl_afu_attach(struct cxl_afu_h *afu, __u64 wed) {

	// Reset AFU
	status.cmd.code = PSL_JOB_RESET;
	status.cmd.addr = 0;
	status.cmd.request = AFU_REQUEST;
	// FIXME: Add timeout
	while (status.cmd.request != AFU_IDLE) short_delay();

	// Start AFU
	status.cmd.code = PSL_JOB_START;
	status.cmd.addr = wed;
	status.cmd.request = AFU_REQUEST;
	// FIXME: Add timeout
	while (status.cmd.request == AFU_REQUEST) short_delay();

	// Wait for job_running
	while (!afu->started) {
		// FIXME: Timeout
		short_delay();
	}

	return 0;
}

void cxl_afu_free(struct cxl_afu_h *afu) {
	// Check for valid AFU
	if (!afu) return;

	// Wait for job_done
	while (afu->started) {
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
	afu->flags = flags;
	afu->mapped = 0;
	if (afu->desc.req_prog_model && 0x0010) {
		// Dedicated Process AFU
		afu->mapped = 0x4000000; // 64MB, AFU Maximum
	}
	else {
		// Only dedicated mode supported for now
		errno = ENOSYS;
		return -1;
	}

	return 0;
}

int cxl_mmio_unmap(struct cxl_afu_h *afu) {
	afu->mapped = 0;

	return 0;
}
void cxl_mmio_write64(struct cxl_afu_h *afu, uint64_t offset, uint64_t data) {
	if (!afu->started)
		return;

#ifdef DEBUG
	printf ("Sending MMIO read double word to AFU\n");
#endif /* #ifdef DEBUG */
	status.mmio.rnw = 0;
	status.mmio.dw = 1;
	offset -= (offset % 2);
	status.mmio.addr = offset;
	if (afu->flags == CXL_MMIO_FLAGS_AFU_LITTLE_ENDIAN)
		status.mmio.data = htole64(data);
	else if (afu->flags == CXL_MMIO_FLAGS_AFU_BIG_ENDIAN)
		status.mmio.data = htobe64(data);
	else
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
}

uint64_t cxl_mmio_read64(struct cxl_afu_h *afu, uint64_t offset) {
	uint64_t value;
	if (!afu->started || ((offset*4)>=afu->mapped)) {
		value = 0xfeedb00ffeedb00full;
	}

#ifdef DEBUG
	printf ("Sending MMIO read double word to AFU\n");
#endif /* #ifdef DEBUG */
	status.mmio.rnw = 1;
	status.mmio.dw = 1;
	offset -= (offset % 2);
	status.mmio.addr = offset;
	status.mmio.request = AFU_REQUEST;
#ifdef DEBUG
	printf ("Waiting for MMIO ack from AFU\n");
#endif /* #ifdef DEBUG */
	// FIXME: Add timeout
	while (status.mmio.request != AFU_IDLE) short_delay();
#ifdef DEBUG
	printf ("MMIO read complete\n");
#endif /* #ifdef DEBUG */
	value = status.mmio.data;
	if (afu->flags == CXL_MMIO_FLAGS_AFU_LITTLE_ENDIAN)
		value = le64toh(value);
	else if (afu->flags == CXL_MMIO_FLAGS_AFU_BIG_ENDIAN)
		value = be64toh(value);
	return value;
}

void cxl_mmio_write32(struct cxl_afu_h *afu, uint64_t offset, uint32_t data) {
	uint64_t value;

	if (!afu->started)
		return;

	value = data;
	value <<= 32;
	value |= data;
#ifdef DEBUG
	printf ("Sending MMIO write single word to AFU\n");
#endif /* #ifdef DEBUG */
	status.mmio.rnw = 0;
	status.mmio.dw = 0;
	status.mmio.addr = offset;
	if (afu->flags == CXL_MMIO_FLAGS_AFU_LITTLE_ENDIAN)
		status.mmio.data = htole64(value);
	else if (afu->flags == CXL_MMIO_FLAGS_AFU_BIG_ENDIAN)
		status.mmio.data = htobe64(value);
	else
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
}

uint32_t cxl_mmio_read32(struct cxl_afu_h *afu, uint64_t offset) {
	uint32_t data;
	if (!afu->started || ((offset*4)>=afu->mapped)) {
		return 0xfeedb00f;
	}

#ifdef DEBUG
	printf ("Sending MMIO read single word to AFU\n");
#endif /* #ifdef DEBUG */
	status.mmio.rnw = 1;
	status.mmio.dw = 0;
	status.mmio.addr = offset;
	status.mmio.request = AFU_REQUEST;
#ifdef DEBUG
	printf ("Waiting for MMIO ack from AFU\n");
#endif /* #ifdef DEBUG */
	// FIXME: Add timeout
	while (status.mmio.request != AFU_IDLE) short_delay();
#ifdef DEBUG
	printf ("MMIO read complete\n");
#endif /* #ifdef DEBUG */
	data = (uint32_t) status.mmio.data;
	if (afu->flags == CXL_MMIO_FLAGS_AFU_LITTLE_ENDIAN)
		data = htole32(data);
	else if (afu->flags == CXL_MMIO_FLAGS_AFU_BIG_ENDIAN)
		data = htobe32(data);
	return data;
}
