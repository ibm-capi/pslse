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
#include <endian.h>
#include <errno.h>
#include <inttypes.h>
#include <malloc.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "libcxl.h"
#include "libcxl_internal.h"
#include "../common/utils.h"

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

#define PSLSE_VERSION 1

static void _delay_1ms() {
	struct timespec ts;
	ts.tv_sec = 0;
	ts.tv_nsec = 1000000;
	nanosleep(&ts, &ts);
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

static void _handle_dsi(struct cxl_afu_h *afu, uint64_t addr)
{
	uint16_t size;

	// Only track a single DSI at a time
	if (afu->dsi != NULL)
		return;

	size = sizeof(struct cxl_event_header) +
	       sizeof(struct cxl_event_data_storage);
	afu->dsi = (struct cxl_event*) malloc(size);
	memset(afu->dsi, 0, size);
	afu->dsi->header.type = CXL_EVENT_DATA_STORAGE;
	afu->dsi->header.size = size;
	afu->dsi->header.process_element = afu->context;
	afu->dsi->fault.addr = addr & FOURK_MASK;
	afu->dsi->fault.dsisr = DSISR;
	if (afu->first_event == NULL)
		afu->first_event = afu->dsi;
}

static void _handle_read(struct cxl_afu_h *afu, uint64_t addr, uint8_t size)
{
	uint8_t buffer[MAX_LINE_CHARS];

	if (!_testmemaddr((uint8_t *) addr)) {
		_handle_dsi(afu, addr);
		DPRINTF("READ from invalid addr @ 0x%016"PRIx64"\n", addr);
		buffer[0] = (uint8_t) PSLSE_MEM_FAILURE;
		if (put_bytes_silent(afu->fd, 1, buffer, 0) != 1) {
			afu->opened = 0;
			afu->attached = 0;
		}
		return;
	}
	buffer[0] = PSLSE_MEM_SUCCESS;
	memcpy(&(buffer[1]), (void *) addr, size);
	if (put_bytes_silent(afu->fd, size+1, buffer, 0) != size+1) {
		afu->opened = 0;
		afu->attached = 0;
	}
	DPRINTF("READ from addr @ 0x%016"PRIx64"\n", addr);
}

static void _handle_write(struct cxl_afu_h *afu, uint64_t addr, uint8_t size,
			 uint8_t *data)
{
	uint8_t buffer;

	if (!_testmemaddr((uint8_t *) addr)) {
		_handle_dsi(afu, addr);
		DPRINTF("WRITE to invalid addr @ 0x%016"PRIx64"\n", addr);
		buffer = PSLSE_MEM_FAILURE;
		if (put_bytes_silent(afu->fd, 1, &buffer, 0) != 1) {
			afu->opened = 0;
			afu->attached = 0;
		}
		return;
	}
	memcpy((void *) addr, data, size);
	buffer = PSLSE_MEM_SUCCESS;
	if (put_bytes_silent(afu->fd, 1, &buffer, 0) != 1) {
		afu->opened = 0;
		afu->attached = 0;
	}
	DPRINTF("WRITE to addr @ 0x%016"PRIx64"\n", addr);
}

static void _handle_touch(struct cxl_afu_h *afu, uint64_t addr, uint8_t size)
{
	uint8_t buffer;

	if (!_testmemaddr((uint8_t *) addr)) {
		_handle_dsi(afu, addr);
		DPRINTF("TOUCH of invalid addr @ 0x%016"PRIx64"\n", addr);
		buffer = (uint8_t) PSLSE_MEM_FAILURE;
		if (put_bytes_silent(afu->fd, 1, &buffer, 0) != 1) {
			afu->opened = 0;
			afu->attached = 0;
		}
		return;
	}
	buffer = PSLSE_MEM_SUCCESS;
	if (put_bytes_silent(afu->fd, 1, &buffer, 0) != 1) {
		afu->opened = 0;
		afu->attached = 0;
	}
	DPRINTF("TOUCH of addr @ 0x%016"PRIx64"\n", addr);
}

static void _handle_ack(struct cxl_afu_h *afu)
{
	uint8_t *data;

	DPRINTF("MMIO ACK\n");
	if (afu->mmio_pending == PSLSE_MMIO_READ64) {
		if ((data = get_bytes_silent(afu->fd, 8, 10000)) == NULL) {
			afu->opened = 0;
			afu->attached = 0;
			afu->mmio_data = 0xFEEDB00FFEEDB00FL;
		}
		else {
			afu->mmio_data = le64toh(*((uint64_t *) data));
		}
	}
	DPRINTF("MMIO ACK0\n");
	if (afu->mmio_pending == PSLSE_MMIO_READ32) {
		if ((data = get_bytes_silent(afu->fd, 4, 10000)) == NULL) {
			afu->opened = 0;
			afu->attached = 0;
			afu->mmio_data = 0xFEEDB00FL;
		}
		else {
			afu->mmio_data = le32toh(*((uint32_t *) data));
		}
	}
	DPRINTF("MMIO ACK1\n");
	afu->mmio_pending = 0;
}

static void _handle_interrupt(struct cxl_afu_h *afu)
{
	uint16_t size, irq;
	uint8_t *data;

	DPRINTF("AFU INTERRUPT\n");
	if ((data = get_bytes_silent(afu->fd, 4, 10000)) == NULL) {
		afu->opened = 0;
		afu->attached = 0;
		return;
	}
	irq = le16toh(*((uint16_t *) data));

	// Only track a single interrupt at a time
	if (afu->irq != NULL)
		return;

	size = sizeof(struct cxl_event_header) +
	       sizeof(struct cxl_event_afu_interrupt);
	afu->irq = (struct cxl_event*) malloc(size);
	memset(afu->irq, 0, size);
	afu->irq->header.type = CXL_EVENT_AFU_INTERRUPT;
	afu->irq->header.size = size;
	afu->irq->header.process_element = afu->context;
	afu->irq->irq.irq = irq;
	if (afu->first_event == NULL)
		afu->first_event = afu->irq;
}

static void *_psl_loop(void *ptr)
{
	struct cxl_afu_h *afu = (struct cxl_afu_h*)ptr;
	uint8_t *buffer;
	uint8_t size;
	uint64_t addr;

	while (afu->opened) {
		pthread_mutex_lock(&(afu->lock));
		// Ensure that afu is still opened under lock
		if (!afu->opened) {
			pthread_mutex_unlock(&(afu->lock));
			break;
		}
		if ((buffer = get_bytes_silent(afu->fd, 1, 10)) == NULL) {
			afu->opened = 0;
			pthread_mutex_unlock(&(afu->lock));
			break;
		}
		if (strlen((char*) buffer)==0) {
			pthread_mutex_unlock(&(afu->lock));
			_delay_1ms();
			continue;
		}
		DPRINTF("PSL EVENT\n");
		switch (buffer[0]) {
		case PSLSE_DETACH:
			free(buffer);
			afu->attached = 0;
			break;
		case PSLSE_MEMORY_READ:
			free(buffer);
			DPRINTF("AFU MEMORY READ\n");
			if ((buffer = get_bytes_silent(afu->fd, 1, 10000))
			    == NULL) {
				afu->opened = 0;
				break;
			}
			size = (uint8_t) buffer[0];
			if ((buffer = get_bytes_silent(afu->fd, 8, 10000))
			    == NULL) {
				afu->opened = 0;
				break;
			}
			addr = le64toh(*((uint64_t *) buffer));
			free(buffer);
			_handle_read(afu, addr, size);
			break;
		case PSLSE_MEMORY_WRITE:
			free(buffer);
			DPRINTF("AFU MEMORY WRITE\n");
			if ((buffer = get_bytes_silent(afu->fd, 1, 10000))
			    == NULL) {
				afu->opened = 0;
				break;
			}
			size = (uint8_t) buffer[0];
			if ((buffer = get_bytes_silent(afu->fd, 8, 10000))
			    == NULL) {
				afu->opened = 0;
				break;
			}
			addr = le64toh(*((uint64_t *) buffer));
			free(buffer);
			if ((buffer = get_bytes_silent(afu->fd, size, 10000))
			    == NULL) {
				afu->opened = 0;
				break;
			}
			_handle_write(afu, addr, size, buffer);
			free(buffer);
			break;
		case PSLSE_MEMORY_TOUCH:
			free(buffer);
			DPRINTF("AFU MEMORY TOUCH\n");
			if ((buffer = get_bytes_silent(afu->fd, 1, 10000))
			    == NULL) {
				afu->opened = 0;
				break;
			}
			size = (uint8_t) buffer[0];
			if ((buffer = get_bytes_silent(afu->fd, 8, 10000))
			    == NULL) {
				afu->opened = 0;
				break;
			}
			addr = le64toh(*((uint64_t *) buffer));
			free(buffer);
			_handle_touch(afu, addr, size);
			break;
		case PSLSE_MMIO_ACK:
			free(buffer);
			_handle_ack(afu);
			break;
		case PSLSE_INTERRUPT:
			free(buffer);
			_handle_interrupt(afu);
			break;
		default:
			free(buffer);
		}
		pthread_mutex_unlock(&(afu->lock));
		_delay_1ms();
	}

	pthread_exit(NULL);
}

struct cxl_afu_h * cxl_afu_open_dev(char *path)
{
	struct cxl_afu_h *afu;
	struct sockaddr_in ssadr;
	struct hostent *he;
	FILE *fp;
	char *afu_id, *host, *port_str;
	uint16_t query16;
	uint8_t *buffer;
	uint8_t query;
	int port;
	size_t size, query_size;

	// Allocate AFU struct
	afu = (struct cxl_afu_h *) malloc(sizeof(struct cxl_afu_h));
	if (!afu) {
		perror("malloc");
		errno = ENOMEM;
		return NULL;
	}
	memset(afu, 0, sizeof(struct cxl_afu_h));

	// Get hostname and port of PSLSE server
	DPRINTF("AFU OPEN\n");
	fp = fopen("pslse_server.dat", "r");
	if (!fp) {
		perror("fopen:pslse_server.dat");
		goto open_fail;
	}
	buffer = (uint8_t*) malloc(MAX_LINE_CHARS);
	memset((char*) buffer, 0, sizeof(buffer));
	if(fgets((char*) buffer, MAX_LINE_CHARS-1, fp) == NULL) {
		perror("fgets:pslse_server.dat");
		fclose(fp);
		goto open_fail;
	}
	fclose(fp);
	host = (char*) buffer;
	port_str = strchr((char*) buffer, ':');
	*port_str = '\0';
	port_str++;
	if (!host || !port_str) {
		fprintf(stderr,"cxl_afu_open_dev:Invalid format in pslse_server.dat\n");
		goto open_fail;
	}
	port = atoi(port_str);
	afu_id = strrchr(path, '/');
	afu_id++;
	printf("Attempting connection to %s on %s:%d\n", afu_id, host, port);

	// Connect to PSLSE server
	if ((he = gethostbyname(host)) == NULL) {
		herror("gethostbyname");
		goto open_fail;
	}
	memset(&ssadr, 0, sizeof(ssadr));
	memcpy(&ssadr.sin_addr, he->h_addr_list[0], he->h_length);
	ssadr.sin_family = AF_INET;
	ssadr.sin_port = htons(port);
	if ((afu->fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		perror("socket");
		goto open_fail;
	}
	ssadr.sin_family = AF_INET;
	ssadr.sin_port = htons(port);
	if (connect(afu->fd, (struct sockaddr *)&ssadr, sizeof(ssadr)) < 0) {
		perror("connect");
		goto open_fail;
	}
	memset((char*) buffer, 0, sizeof(buffer));
	strcpy((char*) buffer, "PSLSE");
	buffer[5] = (uint8_t) PSLSE_VERSION;
	buffer[6] = (uint8_t) strlen(afu_id);
	strcat((char*) buffer, afu_id);
	size = strlen((char*) buffer);
	if (put_bytes_silent(afu->fd, size, buffer, 0) != size) {
		fprintf(stderr,"cxl_afu_open_dev:Failed to write to socket!\n");
		goto open_fail;
	}
	free(buffer);
	if ((buffer = get_bytes_silent(afu->fd, 1, -1)) == NULL) {
		fprintf(stderr,"cxl_afu_open_dev:Socket failed open acknowledge\n");
		close(afu->fd);
		goto open_fail;
	}
	if (buffer[0] != (uint8_t) PSLSE_ATTACH) {
		fprintf(stderr,"cxl_afu_open_dev:PSLSE bad acknowledge\n");
		free(buffer);
		close(afu->fd);
		goto open_fail;
	}
	free(buffer);
	if ((buffer = get_bytes_silent(afu->fd, 1, -1)) == NULL) {
		fprintf(stderr,"cxl_afu_open_dev:Socket failed context retrieve\n");
		close(afu->fd);
		goto open_fail;
	}
	afu->context = buffer[0];
	free(buffer);
	query = PSLSE_QUERY;
	if (put_bytes_silent(afu->fd, 1, &query, 0) != 1) {
		fprintf(stderr,"cxl_afu_open_dev:Failed to write to socket!\n");
		goto open_fail;
	}
	query_size = sizeof(uint8_t)+sizeof(uint16_t);
	if ((buffer = get_bytes_silent(afu->fd, query_size, -1)) == NULL) {
		fprintf(stderr,"cxl_afu_open_dev:Socket failed context retrieve\n");
		close(afu->fd);
		goto open_fail;
	}
	if (buffer[0] != (uint8_t) PSLSE_QUERY) {
		fprintf(stderr,"cxl_afu_open_dev:Bad QUERY acknowledge\n");
		free(buffer);
		close(afu->fd);
		goto open_fail;
	}
	memcpy((char*) &query16, (char*) &(buffer[1]), 2);
	free(buffer);
	afu->irqs_min = (long) le16toh(query16);
	afu->opened = 1;
	afu->api_version = 1;
	afu->api_version_compatible = 1;
	if (pthread_create(&(afu->thread), NULL, _psl_loop, afu)) {
		perror("pthread_create");
		close(afu->fd);
		goto open_fail;
	}
	afu->id = (char *) malloc(strlen(afu_id)+1);
	strcpy(afu->id, afu_id);
	pthread_mutex_init(&(afu->lock), NULL);

	return afu;

open_fail:
	free(afu);
	errno = ENODEV;
	return NULL;
}

void cxl_afu_free(struct cxl_afu_h *afu) {
	uint8_t buffer;
	int rc;

	if (!afu->opened)
		goto free_done;

	DPRINTF("AFU FREE\n");
	buffer = PSLSE_DETACH;
	pthread_mutex_lock(&(afu->lock));
	rc = put_bytes_silent(afu->fd, 1, &buffer, 0);
	pthread_mutex_unlock(&(afu->lock));
	if (rc==1) {
		while (afu->attached)	/*infinite loop*/
			_delay_1ms();
	}
	close(afu->fd);
	afu->opened = 0;
	if (afu->id != NULL)
		free(afu->id);
free_done:
	pthread_join(afu->thread, NULL);
	free(afu);
}

int cxl_afu_opened(struct cxl_afu_h *afu) {
	return afu->opened;
}

int cxl_afu_attach(struct cxl_afu_h *afu, __u64 wed) {
	uint64_t *wed_ptr;
	uint8_t *buffer;

	DPRINTF("AFU ATTACH\n");
	if (!afu->opened) {
		fprintf(stderr,"cxl_afu_attach: Must open AFU first!\n");
		errno = ENODEV;
		return -1;
	}

	if (afu->attached) {
		fprintf(stderr,"cxl_afu_attach: AFU already attached!\n");
		errno = ENODEV;
		return -1;
	}

	buffer = (uint8_t*) malloc(MAX_LINE_CHARS);
	memset((char*) buffer, 0, sizeof(buffer));
	buffer[0] = PSLSE_ATTACH;
	wed_ptr = (uint64_t *) &(buffer[1]);
	*wed_ptr = htole64(wed);
	buffer[9] = '\0';
	pthread_mutex_lock(&(afu->lock));
	if (put_bytes_silent(afu->fd, 9, buffer, 10000) != 9) {
		fprintf(stderr,"cxl_afu_attach: Socket fail on attach!\n");
		afu->opened = 0;
		pthread_mutex_unlock(&(afu->lock));
		errno = ENODEV;
		return -1;
	}
	free(buffer);
	buffer = get_bytes_silent(afu->fd, 1, 10000);
	while ((buffer != NULL) && (buffer[0] == '\0')) {
		free(buffer);
		buffer = get_bytes_silent(afu->fd, 1, 10000);
	}
	if (buffer == NULL) {
		fprintf(stderr,"cxl_afu_attach: Socket fail on attach acknowledge!\n");
		afu->opened = 0;
		pthread_mutex_unlock(&(afu->lock));
		errno = ENODEV;
		return -1;
	}
	if (buffer[0]!=(uint8_t) PSLSE_ATTACH) {
		fprintf(stderr,"cxl_afu_attach: Bad attach acknowledge!\n");
		afu->opened = 0;
		pthread_mutex_unlock(&(afu->lock));
		free(buffer);
		errno = ENODEV;
		return -1;
	}
	free(buffer);
	afu->attached = 1;
	pthread_mutex_unlock(&(afu->lock));
	return 0;
}

int cxl_get_api_version(struct cxl_afu_h *afu, long *valp)
{
	if (afu==NULL)
		return -1;
	*valp = afu->api_version;
	return 0;
}

int cxl_get_api_version_compatible(struct cxl_afu_h *afu, long *valp)
{
	if (afu==NULL)
		return -1;
	*valp = afu->api_version_compatible;
	return 0;
}

int cxl_get_irqs_min(struct cxl_afu_h *afu, long *valp)
{
	if (afu==NULL)
		return -1;
	*valp = afu->irqs_min;
	return 0;
}

int cxl_event_pending(struct cxl_afu_h *afu)
{
	if (afu->first_event == NULL)
		return 0;
	return 1;
}

int cxl_read_event(struct cxl_afu_h *afu, struct cxl_event *event)
{
	if (!event)
		return -1;

	// Function will block until event occurs
	while (afu->first_event == NULL)	/*infinite loop*/
		_delay_1ms();

	// Copy event data, free and move next event, if any, to first
	memcpy(event, afu->first_event, afu->first_event->header.size);
	if (afu->first_event == afu->irq) {
		free(afu->irq);
		afu->first_event = afu->dsi;
	}
	else if (afu->first_event == afu->dsi) {
		free(afu->dsi);
		afu->first_event = afu->irq;
	}
	return 0;
}

int cxl_mmio_map(struct cxl_afu_h *afu, __u32 flags)
{
	uint8_t buffer[MAX_LINE_CHARS];
	uint32_t *flags_ptr;

	DPRINTF("MMIO MAP\n");
	pthread_mutex_lock(&(afu->lock));
	if (!afu->opened) {
		goto map_fail;
	}
	DPRINTF("MMIO MAP0\n");

	if (!afu->attached) {
		printf("cxl_mmio_map: Must attach first!\n");
		goto map_fail;
	}
	DPRINTF("MMIO MAP1\n");

	if (flags & ~(CXL_MMIO_FLAGS)) {
		printf("cxl_mmio_map: Invalid flags!\n");
		goto map_fail;
	}

	buffer[0] = PSLSE_MMIO_MAP;
	flags_ptr = (uint32_t *) &(buffer[1]);
	*flags_ptr = htole32(flags);
	DPRINTF("MMIO MAP2\n");
	if (put_bytes_silent(afu->fd, 5, buffer, 10000) != 5) {
		perror("write");
		close(afu->fd);
		afu->opened = 0;
	}
	DPRINTF("MMIO MAP3\n");
	afu->mmio_pending = PSLSE_MMIO_MAP;
	pthread_mutex_unlock(&(afu->lock));
	while (afu->mmio_pending == PSLSE_MMIO_MAP)
		_delay_1ms();
	DPRINTF("MMIO MAP4\n");

	afu->mapped = 1;
	return 0;
map_fail:
	pthread_mutex_unlock(&(afu->lock));
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
	uint8_t buffer[MAX_LINE_CHARS];
	uint32_t addr;
	uint64_t le_data;

	pthread_mutex_lock(&(afu->lock));
	if ((!afu->mapped) || (offset & 0x7))
		goto write64_fail;
	buffer[0] = PSLSE_MMIO_WRITE64;
	addr = htole32((uint32_t) offset);
	memcpy((char*)&(buffer[1]), (char*)&(addr), 4);
	le_data = htole64(data);
	memcpy((char*)&(buffer[5]), (char*)&(le_data), 8);
	if (put_bytes_silent(afu->fd, 13, buffer, 10000) != 13) {
		perror("write");
		close(afu->fd);
		afu->opened = 0;
		goto write64_fail;
	}
	afu->mmio_pending = PSLSE_MMIO_WRITE64;
	pthread_mutex_unlock(&(afu->lock));
	while (afu->mmio_pending == PSLSE_MMIO_WRITE64)
		_delay_1ms();
	return 0;
write64_fail:
	pthread_mutex_unlock(&(afu->lock));
	errno = EADDRNOTAVAIL;
	return 1;
}

int cxl_mmio_read64(struct cxl_afu_h *afu, uint64_t offset, uint64_t * data)
{
	uint8_t buffer[MAX_LINE_CHARS];
	uint32_t addr;

	pthread_mutex_lock(&(afu->lock));
	if ((!afu->mapped) || (offset & 0x7))
		goto read64_fail;
	buffer[0] = PSLSE_MMIO_READ64;
	addr = htole32((uint32_t) offset);
	memcpy((char*)&(buffer[1]), (char*)&(addr), 4);
	if (put_bytes_silent(afu->fd, 5, buffer, 10000) != 5) {
		perror("write");
		close(afu->fd);
		afu->opened = 0;
		goto read64_fail;
	}
	afu->mmio_pending = PSLSE_MMIO_READ64;
	pthread_mutex_unlock(&(afu->lock));
	while (afu->mmio_pending == PSLSE_MMIO_READ64)
		_delay_1ms();
	*data = afu->mmio_data;
	pthread_mutex_unlock(&(afu->lock));
	return 0;
read64_fail:
	pthread_mutex_unlock(&(afu->lock));
	errno = EADDRNOTAVAIL;
	return 1;
}


int cxl_mmio_write32(struct cxl_afu_h *afu, uint64_t offset, uint32_t data)
{
	uint8_t buffer[MAX_LINE_CHARS];
	uint32_t addr;
	uint32_t le_data;

	pthread_mutex_lock(&(afu->lock));
	if ((!afu->mapped) || (offset & 0x7))
		goto write32_fail;
	buffer[0] = PSLSE_MMIO_WRITE32;
	addr = htole32((uint32_t) offset);
	memcpy((char*)&(buffer[1]), (char*)&(addr), 4);
	le_data = htole32(data);
	memcpy((char*)&(buffer[5]), (char*)&(le_data), 4);
	if (put_bytes_silent(afu->fd, 9, buffer, 10000) != 9) {
		perror("write");
		close(afu->fd);
		afu->opened = 0;
		goto write32_fail;
	}
	afu->mmio_pending = PSLSE_MMIO_WRITE32;
	pthread_mutex_unlock(&(afu->lock));
	while (afu->mmio_pending == PSLSE_MMIO_WRITE32)
		_delay_1ms();
	return 0;
write32_fail:
	pthread_mutex_unlock(&(afu->lock));
	errno = EADDRNOTAVAIL;
	return 1;
}

int cxl_mmio_read32(struct cxl_afu_h *afu, uint64_t offset, uint32_t * data)
{
	uint8_t buffer[MAX_LINE_CHARS];
	uint32_t addr;

	pthread_mutex_lock(&(afu->lock));
	if ((!afu->mapped) || (offset & 0x7))
		goto read32_fail;
	buffer[0] = PSLSE_MMIO_READ32;
	addr = htole32((uint32_t) offset);
	memcpy((char*)&(buffer[1]), (char*)&(addr), 4);
	if (put_bytes_silent(afu->fd, 5, buffer, 10000) != 5) {
		perror("write");
		close(afu->fd);
		afu->opened = 0;
		goto read32_fail;
	}
	afu->mmio_pending = PSLSE_MMIO_READ32;
	pthread_mutex_unlock(&(afu->lock));
	while (afu->mmio_pending == PSLSE_MMIO_READ32)
		_delay_1ms();
	*data = (uint32_t) afu->mmio_data;
	pthread_mutex_unlock(&(afu->lock));
	return 0;
read32_fail:
	pthread_mutex_unlock(&(afu->lock));
	errno = EADDRNOTAVAIL;
	return 1;
}

