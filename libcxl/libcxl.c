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

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "libcxl.h"
#include "libcxl_internal.h"
#include "../common/utils.h"

#define API_VERSION            1
#define API_VERSION_COMPATIBLE 1

#ifdef DEBUG
#define DPRINTF(...) printf(__VA_ARGS__)
#else
#define DPRINTF(...)
#endif

/*
 * System constants
 */

#define MAX_LINE_CHARS 1024

#define FOURK_MASK        0xFFFFFFFFFFFFF000L

#define DSISR 0x4000000040000000L

static int _delay_1ms()
{
	struct timespec ts;
	ts.tv_sec = 0;
	ts.tv_nsec = 1000000;
	return nanosleep(&ts, &ts);
}

static int _testmemaddr(uint8_t * memaddr)
{
	int fd[2];
	int ret = 0;
	if (pipe(fd) >= 0) {
		if (write(fd[1], memaddr, 1) > 0)
			ret = 1;
	}

	close(fd[0]);
	close(fd[1]);

	return ret;
}

static void _all_idle(struct cxl_afu_h *afu)
{
	if (!afu)
		fatal_msg("NULL afu passed to libcxl.c:_all_idle");
	afu->int_req.state = LIBCXL_REQ_IDLE;
	afu->open.state = LIBCXL_REQ_IDLE;
	afu->attach.state = LIBCXL_REQ_IDLE;
	afu->mmio.state = LIBCXL_REQ_IDLE;
	afu->mapped = 0;
	afu->attached = 0;
	afu->opened = 0;
}

static int _handle_dsi(struct cxl_afu_h *afu, uint64_t addr)
{
	uint16_t size;
	int i;

	if (!afu)
		fatal_msg("NULL afu passed to libcxl.c:_handle_dsi");
	// Only track a single DSI at a time
	pthread_mutex_lock(&(afu->event_lock));
	i = 0;
	while (afu->events[i] != NULL) {
		if (afu->events[i]->header.type == CXL_EVENT_DATA_STORAGE) {
			pthread_mutex_unlock(&(afu->event_lock));
			return 0;
		}
		++i;
	}
	assert(i < EVENT_QUEUE_MAX);

	size = sizeof(struct cxl_event_header) +
	    sizeof(struct cxl_event_data_storage);
	afu->events[i] = (struct cxl_event *)calloc(1, size);
	afu->events[i]->header.type = CXL_EVENT_DATA_STORAGE;
	afu->events[i]->header.size = size;
	afu->events[i]->header.process_element = afu->context;
	afu->events[i]->fault.addr = addr & FOURK_MASK;
	afu->events[i]->fault.dsisr = DSISR;

	do {
		i = write(afu->pipe[1], &(afu->events[i]->header.type), 1);
	}
	while ((i == 0) || (errno == EINTR));
	pthread_mutex_unlock(&(afu->event_lock));
	return i;
}

static int _handle_interrupt(struct cxl_afu_h *afu)
{
	uint16_t size, irq;
	uint8_t data[sizeof(irq)];
	int i;

	if (!afu)
		fatal_msg("NULL afu passed to libcxl.c:_handle_interrupt");
	DPRINTF("AFU INTERRUPT\n");
	if (get_bytes_silent(afu->fd, sizeof(irq), data, 1000, 0) < 0) {
		warn_msg("Socket failure getting IRQ");
		_all_idle(afu);
		return -1;
	}
	memcpy(&irq, data, sizeof(irq));
	irq = ntohs(irq);

	// Only track a single interrupt at a time
	pthread_mutex_lock(&(afu->event_lock));
	i = 0;
	while (afu->events[i] != NULL) {
		if (afu->events[i]->header.type == CXL_EVENT_AFU_INTERRUPT) {
			pthread_mutex_unlock(&(afu->event_lock));
			return 0;
		}
		++i;
	}
	assert(i < EVENT_QUEUE_MAX);

	size = sizeof(struct cxl_event_header) +
	    sizeof(struct cxl_event_afu_interrupt);
	afu->events[i] = (struct cxl_event *)calloc(1, size);
	afu->events[i]->header.type = CXL_EVENT_AFU_INTERRUPT;
	afu->events[i]->header.size = size;
	afu->events[i]->header.process_element = afu->context;
	afu->events[i]->irq.irq = irq;

	do {
		i = write(afu->pipe[1], &(afu->events[i]->header.type), 1);
	}
	while ((i == 0) || (errno == EINTR));
	pthread_mutex_unlock(&(afu->event_lock));
	return i;
}

static int _handle_afu_error(struct cxl_afu_h *afu)
{
	uint64_t error;
	uint16_t size;
	uint8_t data[sizeof(error)];
	int i;

	if (!afu)
		fatal_msg("NULL afu passed to libcxl.c:_handle_afu_error");
	DPRINTF("AFU ERROR\n");
	if (get_bytes_silent(afu->fd, sizeof(error), data, 1000, 0) < 0) {
		warn_msg("Socket failure getting AFU ERROR");
		_all_idle(afu);
		return -1;
	}
	memcpy(&error, data, sizeof(error));
	error = ntohll(error);

	// Only track a single AFU error at a time
	pthread_mutex_lock(&(afu->event_lock));
	i = 0;
	while (afu->events[i] != NULL) {
		if (afu->events[i]->header.type == CXL_EVENT_AFU_ERROR) {
			pthread_mutex_unlock(&(afu->event_lock));
			return 0;
		}
		++i;
	}
	assert(i < EVENT_QUEUE_MAX);

	size = sizeof(struct cxl_event_header) +
	    sizeof(struct cxl_event_afu_error);
	afu->events[i] = (struct cxl_event *)calloc(1, size);
	afu->events[i]->header.type = CXL_EVENT_AFU_ERROR;
	afu->events[i]->header.size = size;
	afu->events[i]->header.process_element = afu->context;
	afu->events[i]->afu_error.error = error;

	do {
		i = write(afu->pipe[1], &(afu->events[i]->header.type), 1);
	}
	while ((i == 0) || (errno == EINTR));
	pthread_mutex_unlock(&(afu->event_lock));
	return i;
}

static void _handle_read(struct cxl_afu_h *afu, uint64_t addr, uint8_t size)
{
	uint8_t buffer[MAX_LINE_CHARS];

	if (!afu)
		fatal_msg("NULL afu passed to libcxl.c:_handle_read");
	if (!_testmemaddr((uint8_t *) addr)) {
		if (_handle_dsi(afu, addr) < 0) {
			perror("DSI Failure");
			return;
		}
		DPRINTF("READ from invalid addr @ 0x%016" PRIx64 "\n", addr);
		buffer[0] = (uint8_t) PSLSE_MEM_FAILURE;
		if (put_bytes_silent(afu->fd, 1, buffer) != 1) {
			afu->opened = 0;
			afu->attached = 0;
		}
		return;
	}
	buffer[0] = PSLSE_MEM_SUCCESS;
	memcpy(&(buffer[1]), (void *)addr, size);
	if (put_bytes_silent(afu->fd, size + 1, buffer) != size + 1) {
		afu->opened = 0;
		afu->attached = 0;
	}
	DPRINTF("READ from addr @ 0x%016" PRIx64 "\n", addr);
}

static void _handle_write(struct cxl_afu_h *afu, uint64_t addr, uint8_t size,
			  uint8_t * data)
{
	uint8_t buffer;

	if (!afu)
		fatal_msg("NULL afu passed to libcxl.c:_handle_write");
	if (!_testmemaddr((uint8_t *) addr)) {
		if (_handle_dsi(afu, addr) < 0) {
			perror("DSI Failure");
			return;
		}
		DPRINTF("WRITE to invalid addr @ 0x%016" PRIx64 "\n", addr);
		buffer = PSLSE_MEM_FAILURE;
		if (put_bytes_silent(afu->fd, 1, &buffer) != 1) {
			afu->opened = 0;
			afu->attached = 0;
		}
		return;
	}
	memcpy((void *)addr, data, size);
	buffer = PSLSE_MEM_SUCCESS;
	if (put_bytes_silent(afu->fd, 1, &buffer) != 1) {
		afu->opened = 0;
		afu->attached = 0;
	}
	DPRINTF("WRITE to addr @ 0x%016" PRIx64 "\n", addr);
}

static void _handle_touch(struct cxl_afu_h *afu, uint64_t addr, uint8_t size)
{
	uint8_t buffer;

	if (!afu)
		fatal_msg("NULL afu passed to libcxl.c:_handle_touch");
	if (!_testmemaddr((uint8_t *) addr)) {
		if (_handle_dsi(afu, addr) < 0) {
			perror("DSI Failure");
			return;
		}
		DPRINTF("TOUCH of invalid addr @ 0x%016" PRIx64 "\n", addr);
		buffer = (uint8_t) PSLSE_MEM_FAILURE;
		if (put_bytes_silent(afu->fd, 1, &buffer) != 1) {
			afu->opened = 0;
			afu->attached = 0;
		}
		return;
	}
	buffer = PSLSE_MEM_SUCCESS;
	if (put_bytes_silent(afu->fd, 1, &buffer) != 1) {
		afu->opened = 0;
		afu->attached = 0;
	}
	DPRINTF("TOUCH of addr @ 0x%016" PRIx64 "\n", addr);
}

static void _handle_ack(struct cxl_afu_h *afu)
{
	uint8_t data[sizeof(uint64_t)];

	if (!afu)
		fatal_msg("NULL afu passed to libcxl.c:_handle_ack");
	DPRINTF("MMIO ACK\n");
	if (afu->mmio.type == PSLSE_MMIO_READ64) {
		if (get_bytes_silent(afu->fd, sizeof(uint64_t), data, 1000, 0) <
		    0) {
			warn_msg("Socket failure getting MMIO Ack");
			_all_idle(afu);
			afu->mmio.data = 0xFEEDB00FFEEDB00FL;
		} else {
			memcpy(&(afu->mmio.data), data, sizeof(uint64_t));
			afu->mmio.data = ntohll(afu->mmio.data);
		}
	}
	if (afu->mmio.type == PSLSE_MMIO_READ32) {
		if (get_bytes_silent(afu->fd, sizeof(uint32_t), data, 1000, 0) <
		    0) {
			warn_msg("Socket failure getting MMIO Read 32 data");
			afu->mmio.data = 0xFEEDB00FL;
			_all_idle(afu);
		} else {
			memcpy(&(afu->mmio.data), data, sizeof(uint32_t));
			debug_msg("KEM:0x%08x", afu->mmio.data);
			afu->mmio.data = ntohl(afu->mmio.data);
			debug_msg("KEM:0x%08x", afu->mmio.data);
		}
	}
	afu->mmio.state = LIBCXL_REQ_IDLE;
}

static void _req_max_int(struct cxl_afu_h *afu)
{
	uint8_t *buffer;
	int size;
	uint16_t value;

	if (!afu)
		fatal_msg("NULL afu passed to libcxl.c:_req_max_int");
	size = 1 + sizeof(uint16_t);
	buffer = (uint8_t *) malloc(size);
	buffer[0] = PSLSE_MAX_INT;
	value = htons(afu->int_req.max);
	memcpy((char *)&(buffer[1]), (char *)&value, sizeof(uint16_t));
	if (put_bytes_silent(afu->fd, size, buffer) != size) {
		free(buffer);
		close_socket(&(afu->fd));
		afu->int_req.max = 0;
		_all_idle(afu);
		return;
	}
	free(buffer);
	afu->int_req.state = LIBCXL_REQ_PENDING;
}

static void _pslse_attach(struct cxl_afu_h *afu)
{
	uint8_t *buffer;
	uint64_t *wed_ptr;
	int size, offset;

	if (!afu)
		fatal_msg("NULL afu passed to libcxl.c:_pslse_attach");
	size = 1 + sizeof(uint64_t);
	buffer = (uint8_t *) malloc(size);
	buffer[0] = PSLSE_ATTACH;
	offset = 1;
	wed_ptr = (uint64_t *) & (buffer[offset]);
	*wed_ptr = htonll(afu->attach.wed);
	if (put_bytes_silent(afu->fd, size, buffer) != size) {
		free(buffer);
		close_socket(&(afu->fd));
		afu->opened = 0;
		afu->attached = 0;
		afu->attach.state = LIBCXL_REQ_IDLE;
		return;
	}
	free(buffer);
	afu->attach.state = LIBCXL_REQ_PENDING;
}

static void _mmio_map(struct cxl_afu_h *afu)
{
	uint8_t *buffer;
	uint32_t *flags_ptr;
	uint32_t flags;
	int size;

	if (!afu)
		fatal_msg("NULL afu passed to libcxl.c:_mmio_map");
	size = 1 + sizeof(uint32_t);
	buffer = (uint8_t *) malloc(size);
	buffer[0] = PSLSE_MMIO_MAP;
	flags = (uint32_t) afu->mmio.data;
	flags_ptr = (uint32_t *) & (buffer[1]);
	*flags_ptr = htonl(flags);
	if (put_bytes_silent(afu->fd, size, buffer) != size) {
		free(buffer);
		close_socket(&(afu->fd));
		afu->opened = 0;
		afu->attached = 0;
		afu->mmio.state = LIBCXL_REQ_IDLE;
		return;
	}
	free(buffer);
	afu->mmio.state = LIBCXL_REQ_PENDING;
}

static void _mmio_write64(struct cxl_afu_h *afu)
{
	uint8_t *buffer;
	uint64_t data;
	uint32_t addr;
	int size, offset;

	if (!afu)
		fatal_msg("NULL afu passed to libcxl.c:_mmio_write64");
	size = 1 + sizeof(addr) + sizeof(data);
	buffer = (uint8_t *) malloc(size);
	buffer[0] = PSLSE_MMIO_WRITE64;
	offset = 1;
	addr = htonl(afu->mmio.addr);
	memcpy((char *)&(buffer[offset]), (char *)&addr, sizeof(addr));
	offset += sizeof(addr);
	data = htonll(afu->mmio.data);
	memcpy((char *)&(buffer[offset]), (char *)&data, sizeof(data));
	if (put_bytes_silent(afu->fd, size, buffer) != size) {
		free(buffer);
		close_socket(&(afu->fd));
		afu->opened = 0;
		afu->attached = 0;
		afu->mmio.state = LIBCXL_REQ_IDLE;
		return;
	}
	free(buffer);
	afu->mmio.state = LIBCXL_REQ_PENDING;
}

static void _mmio_write32(struct cxl_afu_h *afu)
{
	uint8_t *buffer;
	uint32_t data;
	uint32_t addr;
	int size, offset;

	if (!afu)
		fatal_msg("NULL afu passed to libcxl.c:_mmio_write32");
	size = 1 + sizeof(addr) + sizeof(data);
	buffer = (uint8_t *) malloc(size);
	buffer[0] = PSLSE_MMIO_WRITE32;
	offset = 1;
	addr = htonl(afu->mmio.addr);
	memcpy((char *)&(buffer[offset]), (char *)&addr, sizeof(addr));
	offset += sizeof(addr);
	data = htonl(afu->mmio.data);
	memcpy((char *)&(buffer[offset]), (char *)&data, sizeof(data));
	if (put_bytes_silent(afu->fd, size, buffer) != size) {
		free(buffer);
		close_socket(&(afu->fd));
		afu->opened = 0;
		afu->attached = 0;
		afu->mmio.state = LIBCXL_REQ_IDLE;
		return;
	}
	free(buffer);
	afu->mmio.state = LIBCXL_REQ_PENDING;
}

static void _mmio_read(struct cxl_afu_h *afu)
{
	uint8_t *buffer;
	uint32_t addr;
	int size, offset;

	if (!afu)
		fatal_msg("NULL afu passed to libcxl.c:_mmio_read");
	size = 1 + sizeof(addr);
	buffer = (uint8_t *) malloc(size);
	buffer[0] = afu->mmio.type;
	offset = 1;
	addr = htonl(afu->mmio.addr);
	memcpy((char *)&(buffer[offset]), (char *)&addr, sizeof(addr));
	if (put_bytes_silent(afu->fd, size, buffer) != size) {
	        warn_msg("_mmio_read: put_bytes_silent failed");
		free(buffer);
		close_socket(&(afu->fd));
		afu->opened = 0;
		afu->attached = 0;
		afu->mmio.state = LIBCXL_REQ_IDLE;
		afu->mmio.data = 0xFEEDB00FFEEDB00FL;
		return;
	}
	free(buffer);
	afu->mmio.state = LIBCXL_REQ_PENDING;
}

static void *_psl_loop(void *ptr)
{
	struct cxl_afu_h *afu = (struct cxl_afu_h *)ptr;
	uint8_t buffer[MAX_LINE_CHARS];
	uint8_t size;
	uint64_t addr;
	uint16_t value;
	uint32_t lvalue;
	int rc;

	if (!afu)
		fatal_msg("NULL afu passed to libcxl.c:_psl_loop");
	afu->opened = 1;
	while (afu->opened) {
		_delay_1ms();
		// Send any requests to PSLSE over socket
		if (afu->int_req.state == LIBCXL_REQ_REQUEST)
			_req_max_int(afu);
		if (afu->attach.state == LIBCXL_REQ_REQUEST)
			_pslse_attach(afu);
		if (afu->mmio.state == LIBCXL_REQ_REQUEST) {
			switch (afu->mmio.type) {
			case PSLSE_MMIO_MAP:
				_mmio_map(afu);
				break;
			case PSLSE_MMIO_WRITE64:
				_mmio_write64(afu);
				break;
			case PSLSE_MMIO_WRITE32:
				_mmio_write32(afu);
				break;
			case PSLSE_MMIO_READ64:
			case PSLSE_MMIO_READ32:	/*fall through */
				_mmio_read(afu);
				break;
			default:
				break;
			}
		}
		// Process socket input from PSLSE
		rc = bytes_ready(afu->fd, 1000, 0);
		if (rc == 0)
			continue;
		if (rc < 0) {
			warn_msg("Socket failure testing bytes_ready");
			_all_idle(afu);
			break;
		}
		if (get_bytes_silent(afu->fd, 1, buffer, 1000, 0) < 0) {
			warn_msg("Socket failure getting PSL event");
			_all_idle(afu);
			break;
		}
		DPRINTF("PSL EVENT\n");
		switch (buffer[0]) {
		case PSLSE_OPEN:
			if (get_bytes_silent(afu->fd, 1, buffer, 1000, 0) < 0) {
				warn_msg("Socket failure getting OPEN context");
				_all_idle(afu);
				break;
			}
			afu->context = (uint16_t) buffer[0];
			afu->open.state = LIBCXL_REQ_IDLE;
			break;
		case PSLSE_ATTACH:
			afu->attach.state = LIBCXL_REQ_IDLE;
			break;
		case PSLSE_DETACH:
		        info_msg("detach response from from pslse");
			afu->mapped = 0;
			afu->attached = 0;
			afu->opened = 0;
			afu->open.state = LIBCXL_REQ_IDLE;
			afu->attach.state = LIBCXL_REQ_IDLE;
			afu->mmio.state = LIBCXL_REQ_IDLE;
			afu->int_req.state = LIBCXL_REQ_IDLE;
			break;
		case PSLSE_MAX_INT:
			size = sizeof(uint16_t);
			if (get_bytes_silent(afu->fd, size, buffer, 1000, 0) <
			    0) {
				warn_msg
				    ("Socket failure getting max interrupt acknowledge");
				_all_idle(afu);
				break;
			}
			memcpy((char *)&value, (char *)buffer,
			       sizeof(uint16_t));
			afu->irqs_max = ntohs(value);
			afu->int_req.state = LIBCXL_REQ_IDLE;
			break;
		case PSLSE_QUERY:
			size = sizeof(uint16_t) + sizeof(uint16_t) + sizeof(uint16_t) 
                           + sizeof(uint16_t) + sizeof(uint32_t);
			if (get_bytes_silent(afu->fd, size, buffer, 1000, 0) <
			    0) {
				warn_msg("Socket failure getting PSLSE query");
				_all_idle(afu);
				break;
			}
			memcpy((char *)&value, (char *)&(buffer[1]), 2);
			afu->irqs_min = (long)ntohs(value);
			memcpy((char *)&value, (char *)&(buffer[3]), 2);
			afu->irqs_max = (long)ntohs(value);
                	memcpy((char *)&value, (char *)&(buffer[4]), 2);
			afu->cr_device = (long)ntohs(value);
                        memcpy((char *)&value, (char *)&(buffer[6]), 2);
			afu->cr_vendor = (long)ntohs(value);
                        memcpy((char *)&lvalue, (char *)&(buffer[8]), 4);
			afu->cr_class = ntohl(lvalue);
			break;
		case PSLSE_MEMORY_READ:
			DPRINTF("AFU MEMORY READ\n");
			if (get_bytes_silent(afu->fd, 1, buffer, 1000, 0) < 0) {
				warn_msg
				    ("Socket failure getting memory read size");
				_all_idle(afu);
				break;
			}
			size = (uint8_t) buffer[0];
			if (get_bytes_silent(afu->fd, sizeof(uint64_t), buffer,
					     -1, 0) < 0) {
				warn_msg
				    ("Socket failure getting memory read addr");
				_all_idle(afu);
				break;
			}
			memcpy((char *)&addr, (char *)buffer, sizeof(uint64_t));
			addr = ntohll(addr);
			_handle_read(afu, addr, size);
			break;
		case PSLSE_MEMORY_WRITE:
			DPRINTF("AFU MEMORY WRITE\n");
			if (get_bytes_silent(afu->fd, 1, buffer, 1000, 0) < 0) {
				warn_msg
				    ("Socket failure getting memory write size");
				_all_idle(afu);
				break;
			}
			size = (uint8_t) buffer[0];
			if (get_bytes_silent(afu->fd, sizeof(uint64_t), buffer,
					     -1, 0) < 0) {
				_all_idle(afu);
				break;
			}
			memcpy((char *)&addr, (char *)buffer, sizeof(uint64_t));
			addr = ntohll(addr);
			if (get_bytes_silent(afu->fd, size, buffer, 1000, 0) <
			    0) {
				warn_msg
				    ("Socket failure getting memory write data");
				_all_idle(afu);
				break;
			}
			_handle_write(afu, addr, size, buffer);
			break;
		case PSLSE_MEMORY_TOUCH:
			DPRINTF("AFU MEMORY TOUCH\n");
			if (get_bytes_silent(afu->fd, 1, buffer, 1000, 0) < 0) {
				warn_msg
				    ("Socket failure getting memory touch size");
				_all_idle(afu);
				break;
			}
			size = buffer[0];
			if (get_bytes_silent(afu->fd, sizeof(uint64_t), buffer,
					     -1, 0) < 0) {
				warn_msg
				    ("Socket failure getting memory touch addr");
				_all_idle(afu);
				break;
			}
			memcpy((char *)&addr, (char *)buffer, sizeof(uint64_t));
			addr = ntohll(addr);
			_handle_touch(afu, addr, size);
			break;
		case PSLSE_MMIO_ACK:
			_handle_ack(afu);
			break;
		case PSLSE_INTERRUPT:
			if (_handle_interrupt(afu) < 0) {
				perror("Interrupt Failure");
				goto psl_fail;
			}
			break;
		case PSLSE_AFU_ERROR:
			if (_handle_afu_error(afu) < 0) {
				perror("AFU ERROR Failure");
				goto psl_fail;
			}
			break;
		default:
			break;
		}
	}

 psl_fail:
	afu->attached = 0;
	pthread_exit(NULL);
}

static int _pslse_connect(uint16_t * afu_map, int *fd)
{
	FILE *fp;
	uint8_t buffer[MAX_LINE_CHARS];
	struct sockaddr_in ssadr;
	struct hostent *he;
	char *host, *port_str;
	int port;

	// Get hostname and port of PSLSE server
	DPRINTF("AFU CONNECT\n");
	fp = fopen("pslse_server.dat", "r");
	if (!fp) {
		perror("fopen:pslse_server.dat");
		goto connect_fail;
	}
	do {
		if (fgets((char *)buffer, MAX_LINE_CHARS - 1, fp) == NULL) {
			perror("fgets:pslse_server.dat");
			fclose(fp);
			goto connect_fail;
		}
	}
	while (buffer[0] == '#');
	fclose(fp);
	host = (char *)buffer;
	port_str = strchr((char *)buffer, ':');
	*port_str = '\0';
	port_str++;
	if (!host || !port_str) {
		warn_msg
		    ("cxl_afu_open_dev:Invalid format in pslse_server.data");
		goto connect_fail;
	}
	port = atoi(port_str);

	info_msg("Connecting to host '%s' port %d", host, port);

	// Connect to PSLSE server
	if ((he = gethostbyname(host)) == NULL) {
		herror("gethostbyname");
		puts(host);
		goto connect_fail;
	}
	memset(&ssadr, 0, sizeof(ssadr));
	memcpy(&ssadr.sin_addr, he->h_addr_list[0], he->h_length);
	ssadr.sin_family = AF_INET;
	ssadr.sin_port = htons(port);
	if ((*fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		perror("socket");
		goto connect_fail;
	}
	ssadr.sin_family = AF_INET;
	ssadr.sin_port = htons(port);
	if (connect(*fd, (struct sockaddr *)&ssadr, sizeof(ssadr)) < 0) {
		perror("connect");
		goto connect_fail;
	}
	strcpy((char *)buffer, "PSLSE");
	buffer[5] = (uint8_t) PSLSE_VERSION_MAJOR;
	buffer[6] = (uint8_t) PSLSE_VERSION_MINOR;
	if (put_bytes_silent(*fd, 7, buffer) != 7) {
		warn_msg("cxl_afu_open_dev:Failed to write to socket!");
		goto connect_fail;
	}
	if (get_bytes_silent(*fd, 1, buffer, -1, 0) < 0) {
		warn_msg("cxl_afu_open_dev:Socket failed open acknowledge");
		close_socket(fd);
		goto connect_fail;
	}
	if (buffer[0] != (uint8_t) PSLSE_CONNECT) {
		warn_msg("cxl_afu_open_dev:PSLSE bad acknowledge");
		close_socket(fd);
		goto connect_fail;
	}
	if (get_bytes_silent(*fd, sizeof(uint16_t), buffer, 1000, 0) < 0) {
		warn_msg("cxl_afu_open_dev:afu_map");
		close_socket(fd);
		goto connect_fail;
	}
	memcpy((char *)afu_map, (char *)buffer, 2);
	*afu_map = (long)ntohs(*afu_map);
	return 0;

 connect_fail:
	errno = ENODEV;
	return -1;
}

static struct cxl_adapter_h *_new_adapter(uint16_t afu_map, uint16_t position,
					  int fd)
{
	struct cxl_adapter_h *adapter;
	uint16_t mask = 0xf000;
	int id_num = 0;

	if (position == 0)
		return NULL;

	adapter = (struct cxl_adapter_h *)
	    calloc(1, sizeof(struct cxl_adapter_h));
	while ((position & mask) == 0) {
		mask >>= 4;
		++id_num;
	}
	adapter->map = afu_map;
	adapter->position = position;
	adapter->mask = mask;
	adapter->fd = fd;
	adapter->id = calloc(6, sizeof(char));
	sprintf(adapter->id, "card%d", id_num);
	return adapter;
}

static struct cxl_afu_h *_new_afu(uint16_t afu_map, uint16_t position, int fd)
{
	uint8_t *buffer;
	int size;
	struct cxl_afu_h *afu;
	uint16_t adapter_mask = 0xf000;
	uint16_t afu_mask = 0x8000;
	int major = 0;
	int minor = 0;

	if (position == 0) {
		errno = ENODEV;
		return NULL;
	}
	while ((position & adapter_mask) == 0) {
		adapter_mask >>= 4;
		afu_mask >>= 4;
		++major;
	}
	while ((position & afu_mask) == 0) {
		afu_mask >>= 1;
		++minor;
	}
	afu = (struct cxl_afu_h *)
	    calloc(1, sizeof(struct cxl_afu_h));
	if (afu == NULL) {
		errno = ENOMEM;
		return NULL;
	}

	if (pipe(afu->pipe) < 0)
		return NULL;

	pthread_mutex_init(&(afu->event_lock), NULL);
	afu->fd = fd;
	afu->map = afu_map;
	afu->dbg_id = (major << 4) | minor;
	debug_msg("opened host-side socket %d", afu->fd);

	// Send PSLSE query
	size = 1 + sizeof(uint8_t);
	buffer = (uint8_t *) malloc(size);
	buffer[0] = PSLSE_QUERY;
	buffer[1] = afu->dbg_id;
	if (put_bytes_silent(afu->fd, size, buffer) != size) {
		free(buffer);
		close_socket(&(afu->fd));
		errno = ENODEV;
		return NULL;
	}
	free(buffer);

	afu->adapter = major;
	afu->position = position;
	afu->id = calloc(7, sizeof(char));
	_all_idle(afu);
	sprintf(afu->id, "afu%d.%d", major, minor);

	return afu;
}

static void _release_afus(struct cxl_afu_h *afu)
{
	struct cxl_afu_h *current;
	uint8_t rc = PSLSE_DETACH;
	int adapter;

	if (afu == NULL)
		return;

	current = afu->_head;
	while (current->adapter < afu->adapter)
		current = current->_next;

	adapter = afu->adapter;
	current = afu;
	while ((current != NULL) && (current->adapter == adapter)) {
		afu = current;
		current = current->_next;
		if (afu->fd) {
			put_bytes_silent(afu->fd, 1, &rc);
			close_socket(&(afu->fd));
		}
		if (afu->id)
			free(afu->id);
		pthread_mutex_destroy(&(afu->event_lock));
		free(afu);
	}
}

static void _release_adapters(struct cxl_adapter_h *adapter)
{
	struct cxl_adapter_h *current;
	uint8_t rc = PSLSE_DETACH;

	if (!adapter)
		fatal_msg("NULL adapter passed to libcxl.c:_release_adapters");
	_release_afus(adapter->afu_list);
	current = adapter;
	while (current != NULL) {
		adapter = current;
		current = current->_next;
		// Disconnect from PSLSE
		if (adapter->fd) {
			put_bytes_silent(adapter->fd, 1, &rc);
			close_socket(&(adapter->fd));
		}
		free(adapter->id);
		free(adapter);
	}
}

static struct cxl_afu_h *_pslse_open(int *fd, uint16_t afu_map, uint8_t major,
				     uint8_t minor, char afu_type)
{
	struct cxl_afu_h *afu;
	uint8_t *buffer;
	uint16_t position;

	if (!fd)
		fatal_msg("NULL fd passed to libcxl.c:_pslse_open");
	position = 0x8000;
	position >>= 4 * major;
	position >>= minor;
	if ((afu_map & position) != position) {
		warn_msg("open:AFU not in system");
		close_socket(fd);
		errno = ENODEV;
		return NULL;
	}
	// Create struct for AFU
	afu = _new_afu(afu_map, position, *fd);
	if (afu == NULL)
		return NULL;

	buffer = (uint8_t *) calloc(1, MAX_LINE_CHARS);
	buffer[0] = (uint8_t) PSLSE_OPEN;
	buffer[1] = afu->dbg_id;
	buffer[2] = afu_type;
	afu->fd = *fd;
	if (put_bytes_silent(afu->fd, 3, buffer) != 3) {
		warn_msg("open:Failed to write to socket");
		free(buffer);
		goto open_fail;
	}
	free(buffer);

	afu->_head = afu;
	afu->adapter = major;
	afu->id = (char *)malloc(7);
	afu->open.state = LIBCXL_REQ_PENDING;

	// Start thread
	if (pthread_create(&(afu->thread), NULL, _psl_loop, afu)) {
		perror("pthread_create");
		close_socket(&(afu->fd));
		goto open_fail;
	}
	// Wait for open acknowledgement
	while (afu->open.state != LIBCXL_REQ_IDLE)	/*infinite loop */
		_delay_1ms();

	if (!afu->opened) {
		pthread_join(afu->thread, NULL);
		goto open_fail;
	}

	sprintf(afu->id, "afu%d.%d", major, minor);

	return afu;

 open_fail:
	pthread_mutex_destroy(&(afu->event_lock));
	free(afu);
	errno = ENODEV;
	return NULL;
}

struct cxl_adapter_h *cxl_adapter_next(struct cxl_adapter_h *adapter)
{
	struct cxl_adapter_h *head;
	uint16_t afu_map, afu_mask;
	int fd;

	// First adapter
	if (adapter == NULL) {
		// Query PSLSE
		if (_pslse_connect(&afu_map, &fd) < 0)
			return NULL;
		// No devices?
		assert(afu_map != 0);
		afu_mask = 0x8000;
		// Find first AFU and return struct for it
		while ((afu_map & afu_mask) != afu_mask)
			afu_mask >>= 1;
		head = _new_adapter(afu_map, afu_mask, fd);
		head->_head = head;
		return head;
	}
	// Return next adapter if already set
	if (adapter->_next != NULL) {
		adapter->_next->fd = adapter->fd;
		adapter->fd = 0;
		return adapter->_next;
	}
	// Find next adapter
	afu_mask = adapter->position;
	afu_map = adapter->map;
	while (((afu_mask & ~adapter->mask) == 0) && (afu_mask != 0))
		afu_mask >>= 1;

	// Find first AFU on another adapter
	while (((afu_map & afu_mask) != afu_mask) && (afu_mask != 0))
		afu_mask >>= 1;

	// No more AFUs
	if (afu_mask == 0) {
		_release_adapters(adapter->_head);
		return NULL;
	}
	// Update pointers and return next adapter
	adapter->_next = _new_adapter(afu_map, afu_mask, adapter->fd);
	adapter->_next->_head = adapter->_head;
	adapter->fd = 0;
	return adapter->_next;
}

char *cxl_adapter_dev_name(struct cxl_adapter_h *adapter)
{
	if (adapter == NULL)
		return NULL;

	return adapter->id;
}

void cxl_adapter_free(struct cxl_adapter_h *adapter)
{
	struct cxl_adapter_h *head, *current;

	if (adapter == NULL)
		return;

	// If removing head then update all head pointers to next
	current = head = adapter->_head;
	while ((head == adapter) && (current != NULL)) {
		current->_head = head->_next;
		current = current->_next;
	}

	// Update list to skip adapter being removed
	current = adapter->_head;
	while (current != NULL) {
		if (current->_next == adapter)
			current->_next = adapter->_next;
		current = current->_next;
	}

	// Free memory for adapter
	_release_afus(adapter->afu_list);
	if (adapter->id)
		free(adapter->id);
	close_socket(&(adapter->fd));
	free(adapter);
}

struct cxl_afu_h *cxl_adapter_afu_next(struct cxl_adapter_h *adapter,
				       struct cxl_afu_h *afu)
{
	struct cxl_afu_h *head;
	uint16_t afu_map, afu_mask;
	int fd;

	if (adapter == NULL)
		return NULL;

	afu_mask = adapter->position;

	// Query PSLSE
	if (adapter->fd == 0) {
		if (_pslse_connect(&afu_map, &fd) < 0)
			return NULL;
	} else {
		afu_map = adapter->map;
	}

	// First afu
	if (afu == NULL) {
		// No devices?
		assert(afu_map != 0);
		// Find first AFU and return struct for it
		afu_mask = adapter->mask & 0x8888;
		while ((afu_map & afu_mask) != afu_mask)
			afu_mask >>= 1;
		head = _new_afu(afu_map, afu_mask, adapter->fd);
		adapter->fd = 0;
		head->_head = head;
		if (head != NULL)
			head->_head = head;
		return head;
	}
	// Return next afu if already set
	if (afu->_next != NULL) {
		afu->_next->fd = afu->fd;
		afu->fd = 0;
		return afu->_next;
	}
	// Find next afu on this adapter
	afu_mask = afu->position >> 1;
	while (((afu_mask & adapter->mask) != 0)
	       && ((afu_mask & afu->map) == 0))
		afu_mask >>= 1;

	// No more AFUs on this adapter
	if ((afu_mask & adapter->mask) == 0) {
		_release_afus(adapter->afu_list);
		return NULL;
	}
	// Update pointers and return next afu
	afu->_next = _new_afu(afu_map, afu_mask, afu->fd);
	afu->_next->_head = afu->_head;
	afu->fd = 0;
	return afu->_next;
}

struct cxl_afu_h *cxl_afu_next(struct cxl_afu_h *afu)
{
	struct cxl_afu_h *head;
	uint16_t afu_map, afu_mask;
	int fd;

	if ((afu == NULL) || (afu->fd == 0)) {
		// Query PSLSE
		if (_pslse_connect(&afu_map, &fd) < 0)
			return NULL;
	} else {
		afu_map = afu->map;
	}

	// First afu
	if (afu == NULL) {
		// No devices?
		assert(afu_map != 0);
		afu_mask = 0x8000;
		// Find first AFU and return struct for it
		while ((afu_map & afu_mask) != afu_mask)
			afu_mask >>= 1;
		head = _new_afu(afu_map, afu_mask, fd);
		head->_head = head;
		return head;
	}
	// Return next afu if already set
	if (afu->_next != NULL) {
		afu->_next->fd = afu->fd;
		afu->fd = 0;
		return afu->_next;
	}
	// Find next afu
	afu_mask = afu->position;
	afu_mask >>= 1;
	while ((afu_mask != 0) && ((afu_mask & afu->map) == 0))
		afu_mask >>= 1;

	// No more AFUs
	if (afu_mask == 0) {
		_release_afus(afu->_head);
		return NULL;
	}
	// Update pointers and return next afu
	afu->_next = _new_afu(afu_map, afu_mask, afu->fd);
	afu->_next->_head = afu->_head;
	afu->fd = 0;
	return afu->_next;
}

char *cxl_afu_dev_name(struct cxl_afu_h *afu)
{
	if (!afu) {
		errno = EINVAL;
		return NULL;
	}
	return afu->id;
}

struct cxl_afu_h *cxl_afu_open_dev(char *path)
{
	uint16_t afu_map;
	uint8_t major, minor;
	char *afu_id;
	char afu_type;
	int fd;

	if (!path)
		return NULL;
	if (_pslse_connect(&afu_map, &fd) < 0)
		return NULL;

	// Discover AFU position
	afu_id = strrchr(path, '/');
	afu_id++;
	if ((afu_id[3] < '0') || (afu_id[3] > '3')) {
		warn_msg("Invalid afu major: %c", afu_id[3]);
		errno = ENODEV;
		return NULL;
	}
	if ((afu_id[5] < '0') || (afu_id[5] > '3')) {
		warn_msg("Invalid afu minor: %c", afu_id[5]);
		errno = ENODEV;
		return NULL;
	}
	major = afu_id[3] - '0';
	minor = afu_id[5] - '0';
	afu_type = afu_id[6];

	return _pslse_open(&fd, afu_map, major, minor, afu_type);
}

struct cxl_afu_h *cxl_afu_open_h(struct cxl_afu_h *afu, enum cxl_views view)
{
	uint8_t major, minor;
	uint16_t mask;
	char afu_type;

	if (afu == NULL) {
		errno = EINVAL;
		return NULL;
	}
	// Query PSLSE
	if (afu->fd == 0) {
		if (_pslse_connect(&(afu->map), &afu->fd) < 0)
			return NULL;
	}

	mask = 0xf000;
	major = minor = 0;
	while (((mask & afu->position) != afu->position) && (mask != 0)) {
		mask >>= 4;
		major++;
	}
	mask &= 0x8888;
	while (((mask & afu->position) != afu->position) && (mask != 0)) {
		mask >>= 1;
		minor++;
	}
	switch (view) {
	case CXL_VIEW_DEDICATED:
		afu_type = 'd';
		break;
	case CXL_VIEW_MASTER:
		afu_type = 'm';
		break;
	case CXL_VIEW_SLAVE:
		afu_type = 's';
		break;
	default:
		errno = ENODEV;
		return NULL;
	}
	return _pslse_open(&(afu->fd), afu->map, major, minor, afu_type);
}

void cxl_afu_free(struct cxl_afu_h *afu)
{
	uint8_t buffer;
	int rc;

	if (!afu) {
		warn_msg("cxl_afu_free: No AFU given");
		goto free_done_no_afu;
	}
	if (!afu->opened)
		goto free_done;

	DPRINTF("AFU FREE\n");
	buffer = PSLSE_DETACH;
	rc = put_bytes_silent(afu->fd, 1, &buffer);
	if (rc == 1) {
	        debug_msg("detach request sent from from host on socket %d", afu->fd);
		while (afu->attached)	/*infinite loop */
			_delay_1ms();
	}
	debug_msg("closing host side socket %d", afu->fd);
	close_socket(&(afu->fd));
	afu->opened = 0;
	pthread_join(afu->thread, NULL);

 free_done:
	if (afu->id != NULL)
		free(afu->id);
 free_done_no_afu:
	pthread_mutex_destroy(&(afu->event_lock));
	free(afu);
}

int cxl_afu_opened(struct cxl_afu_h *afu)
{
	if (!afu) {
		errno = EINVAL;
		return -1;
	}
	return afu->opened;
}

int cxl_afu_attach(struct cxl_afu_h *afu, uint64_t wed)
{
	if (!afu) {
		errno = EINVAL;
		return -1;
	}
	DPRINTF("AFU ATTACH\n");
	if (!afu->opened) {
		warn_msg("cxl_afu_attach: Must open AFU first");
		errno = ENODEV;
		return -1;
	}

	if (afu->attached) {
		warn_msg("cxl_afu_attach: AFU already attached");
		errno = ENODEV;
		return -1;
	}
	// Perform PSLSE attach
	afu->attach.wed = wed;
	afu->attach.state = LIBCXL_REQ_REQUEST;
	while (afu->attach.state != LIBCXL_REQ_IDLE)	/*infinite loop */
		_delay_1ms();
	afu->attached = 1;

	return 0;
}

int cxl_afu_attach_full(struct cxl_afu_h *afu, uint64_t wed,
			uint16_t num_interrupts, uint64_t amr)
{
	if (!afu) {
		errno = EINVAL;
		return -1;
	}
	// Request maximum interrupts
	afu->int_req.max = num_interrupts;

	return cxl_afu_attach(afu, wed);
}

int cxl_afu_get_process_element(struct cxl_afu_h *afu)
{
	DPRINTF("AFU GET PROCESS ELEMENT\n");
	if (!afu->opened) {
		warn_msg("cxl_afu_get_process_element: Must open AFU first");
		errno = ENODEV;
		return -1;
	}

	if (!afu->attached) {
		warn_msg("cxl_afu_get_process_element: Must attach AFU first");
		errno = ENODEV;
		return -1;
	}
	return afu->context;
}

int cxl_afu_fd(struct cxl_afu_h *afu)
{
	if (!afu) {
		warn_msg("cxl_afu_attach_full: No AFU given");
		errno = ENODEV;
		return -1;
	}
	return afu->pipe[0];
}

int cxl_get_api_version(struct cxl_afu_h *afu, long *valp)
{
	if ((afu == NULL) || (afu->opened))
		return -1;
	*valp = API_VERSION;
	return 0;
}

int cxl_get_api_version_compatible(struct cxl_afu_h *afu, long *valp)
{
	if ((afu == NULL) || (afu->opened))
		return -1;
	*valp = API_VERSION_COMPATIBLE;
	return 0;
}

int cxl_get_irqs_max(struct cxl_afu_h *afu, long *valp)
{
	if ((afu == NULL) || (afu->opened))
		return -1;
	*valp = afu->irqs_max;
	return 0;
}

int cxl_get_irqs_min(struct cxl_afu_h *afu, long *valp)
{
	if ((afu == NULL) || (afu->opened))
		return -1;
	*valp = afu->irqs_min;
	return 0;
}

int cxl_event_pending(struct cxl_afu_h *afu)
{
	if (afu->events[0] != NULL)
		return 1;

	return 0;
}

int cxl_read_event(struct cxl_afu_h *afu, struct cxl_event *event)
{
	uint8_t type;
	int i;

	if (afu == NULL || event == NULL) {
		errno = EINVAL;
		return -1;
	}
	// Function will block until event occurs
	pthread_mutex_lock(&(afu->event_lock));
	while (afu->opened && !afu->events[0]) {	/*infinite loop */
		pthread_mutex_unlock(&(afu->event_lock));
		if (_delay_1ms() < 0)
			return -1;
		pthread_mutex_lock(&(afu->event_lock));
	}

	// Copy event data, free and move remaining events in queue
	memcpy(event, afu->events[0], afu->events[0]->header.size);
	free(afu->events[0]);
	for (i = 1; i < EVENT_QUEUE_MAX; i++)
		afu->events[i - 1] = afu->events[i];
	afu->events[EVENT_QUEUE_MAX - 1] = NULL;
	pthread_mutex_unlock(&(afu->event_lock));
	if (read(afu->pipe[0], &type, 1) > 0)
		return 0;
	return -1;
}

int cxl_read_expected_event(struct cxl_afu_h *afu, struct cxl_event *event,
			    uint32_t type, uint16_t irq)
{
	if (!afu)
		return -1;
	if (cxl_read_event(afu, event) < 0)
		return -1;

	if (event->header.type != type)
		return -1;

	if ((event->header.type == CXL_EVENT_AFU_INTERRUPT) &&
	    (event->irq.irq != irq))
		return -1;

	return 0;
}

int cxl_mmio_map(struct cxl_afu_h *afu, uint32_t flags)
{
	DPRINTF("MMIO MAP\n");
	if (!afu->opened) {
		printf("cxl_mmio_map: Must open first!\n");
		goto map_fail;
	}

	if (!afu->attached) {
		printf("cxl_mmio_map: Must attach first!\n");
		goto map_fail;
	}

	if (flags & ~(CXL_MMIO_FLAGS)) {
		printf("cxl_mmio_map: Invalid flags!\n");
		goto map_fail;
	}
	// Send MMIO map to PSLSE
	afu->mmio.type = PSLSE_MMIO_MAP;
	afu->mmio.data = (uint64_t) flags;
	afu->mmio.state = LIBCXL_REQ_REQUEST;
	while (afu->mmio.state != LIBCXL_REQ_IDLE)	/*infinite loop */
		_delay_1ms();
	afu->mapped = 1;

	return 0;
 map_fail:
	errno = ENODEV;
	return -1;
}

int cxl_mmio_unmap(struct cxl_afu_h *afu)
{
	afu->mapped = 0;
	return 0;
}

int cxl_mmio_write64(struct cxl_afu_h *afu, uint64_t offset, uint64_t data)
{
	if (offset & 0x7) {
		errno = EINVAL;
		return -1;
	}
	if ((afu == NULL) || !afu->mapped)
		goto write64_fail;

	// Send MMIO map to PSLSE
	afu->mmio.type = PSLSE_MMIO_WRITE64;
	afu->mmio.addr = (uint32_t) offset;
	afu->mmio.data = data;
	afu->mmio.state = LIBCXL_REQ_REQUEST;
	while (afu->mmio.state != LIBCXL_REQ_IDLE)	/*infinite loop */
		_delay_1ms();

	if (!afu->opened)
		goto write64_fail;

	return 0;

 write64_fail:
	errno = ENODEV;
	return -1;
}

int cxl_mmio_read64(struct cxl_afu_h *afu, uint64_t offset, uint64_t * data)
{
	if (offset & 0x7) {
		errno = EINVAL;
		return -1;
	}
	if ((afu == NULL) || !afu->mapped)
		goto read64_fail;

	// Send MMIO map to PSLSE
	afu->mmio.type = PSLSE_MMIO_READ64;
	afu->mmio.addr = (uint32_t) offset;
	afu->mmio.state = LIBCXL_REQ_REQUEST;
	while (afu->mmio.state != LIBCXL_REQ_IDLE)	/*infinite loop */
		_delay_1ms();
	*data = afu->mmio.data;

	if (!afu->opened)
		goto read64_fail;

	return 0;

 read64_fail:
	errno = ENODEV;
	return -1;
}

int cxl_mmio_write32(struct cxl_afu_h *afu, uint64_t offset, uint32_t data)
{
	if (offset & 0x3) {
		errno = EINVAL;
		return -1;
	}
	if ((afu == NULL) || !afu->mapped)
		goto write32_fail;

	// Send MMIO map to PSLSE
	afu->mmio.type = PSLSE_MMIO_WRITE32;
	afu->mmio.addr = (uint32_t) offset;
	afu->mmio.data = (uint64_t) data;
	afu->mmio.state = LIBCXL_REQ_REQUEST;
	while (afu->mmio.state != LIBCXL_REQ_IDLE)	/*infinite loop */
		_delay_1ms();

	if (!afu->opened)
		goto write32_fail;

	return 0;

 write32_fail:
	errno = ENODEV;
	return -1;
}

int cxl_mmio_read32(struct cxl_afu_h *afu, uint64_t offset, uint32_t * data)
{
	if (offset & 0x3) {
		errno = EINVAL;
		return -1;
	}
	if ((afu == NULL) || !afu->mapped)
		goto read32_fail;

	// Send MMIO map to PSLSE
	afu->mmio.type = PSLSE_MMIO_READ32;
	afu->mmio.addr = (uint32_t) offset;
	afu->mmio.state = LIBCXL_REQ_REQUEST;
	while (afu->mmio.state != LIBCXL_REQ_IDLE)	/*infinite loop */
		_delay_1ms();
	*data = (uint32_t) afu->mmio.data;

	if (!afu->opened)
		goto read32_fail;

	return 0;

 read32_fail:
	errno = ENODEV;
	return -1;
}

int cxl_get_cr_device(struct cxl_afu_h *afu, long cr_num, long *valp)
{
	if (afu == NULL) 
		return -1;
        //uint16_t crnum = cr_num;
	// For now, don't worry about cr_num
	*valp =  afu->cr_device;
	return 0;
}

int cxl_get_cr_vendor(struct cxl_afu_h *afu, long cr_num, long *valp)
{
	if (afu == NULL) 
		return -1;
        //uint16_t crnum = cr_num;
	// For now, don't worry about cr_num
	*valp =  afu->cr_vendor;
	return 0;
}

int cxl_get_cr_class(struct cxl_afu_h *afu, long cr_num, long *valp)
{
	if (afu == NULL) 
		return -1;
        //uint16_t crnum = cr_num;
	// For now, don't worry about cr_num
	*valp =  afu->cr_class;
	return 0;
}

int cxl_get_mmio_size(struct cxl_afu_h *afu, long *valp)
{
	if (afu == NULL)
                   return -1;
        // for now just return constant, later will read value from file
        *valp = 0x04000000;
        return 0;
}

