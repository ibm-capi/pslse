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
	afu->dsi = (struct cxl_event*) calloc(1, size);
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
		if (put_bytes_silent(afu->fd, 1, buffer, -1) != 1) {
			afu->opened = 0;
			afu->attached = 0;
		}
		return;
	}
	buffer[0] = PSLSE_MEM_SUCCESS;
	memcpy(&(buffer[1]), (void *) addr, size);
	if (put_bytes_silent(afu->fd, size+1, buffer, -1) != size+1) {
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
		if (put_bytes_silent(afu->fd, 1, &buffer, -1) != 1) {
			afu->opened = 0;
			afu->attached = 0;
		}
		return;
	}
	memcpy((void *) addr, data, size);
	buffer = PSLSE_MEM_SUCCESS;
	if (put_bytes_silent(afu->fd, 1, &buffer, -1) != 1) {
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
		if (put_bytes_silent(afu->fd, 1, &buffer, -1) != 1) {
			afu->opened = 0;
			afu->attached = 0;
		}
		return;
	}
	buffer = PSLSE_MEM_SUCCESS;
	if (put_bytes_silent(afu->fd, 1, &buffer, -1) != 1) {
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
		if ((data = get_bytes_silent(afu->fd, 8, -1)) == NULL) {
			afu->opened = 0;
			afu->attached = 0;
			afu->mmio_data = 0xFEEDB00FFEEDB00FL;
		}
		else {
			afu->mmio_data = le64toh(*((uint64_t *) data));
			free(data);
		}
	}
	if (afu->mmio_pending == PSLSE_MMIO_READ32) {
		if ((data = get_bytes_silent(afu->fd, 4, -1)) == NULL) {
			afu->opened = 0;
			afu->attached = 0;
			afu->mmio_data = 0xFEEDB00FL;
		}
		else {
			afu->mmio_data = le32toh(*((uint32_t *) data));
			free(data);
		}
	}
	afu->mmio_pending = 0;
}

static void _handle_interrupt(struct cxl_afu_h *afu)
{
	uint16_t size, irq;
	uint8_t *data;

	DPRINTF("AFU INTERRUPT\n");
	if ((data = get_bytes_silent(afu->fd, 4, -1)) == NULL) {
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
	afu->irq = (struct cxl_event*) calloc(1, size);
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

	pthread_mutex_lock(&(afu->lock));
	while (afu->opened) {
		if ((buffer = get_bytes_silent(afu->fd, 1, 0)) == NULL) {
			afu->opened = 0;
			pthread_mutex_unlock(&(afu->lock));
			break;
		}
		if (strlen((char*) buffer)==0) {
			free(buffer);
			pthread_mutex_unlock(&(afu->lock));
			_delay_1ms();
			pthread_mutex_lock(&(afu->lock));
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
			if ((buffer = get_bytes_silent(afu->fd, 1, -1))
			    == NULL) {
				afu->opened = 0;
				break;
			}
			size = (uint8_t) buffer[0];
			free(buffer);
			if ((buffer = get_bytes_silent(afu->fd, 8, -1))
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
			if ((buffer = get_bytes_silent(afu->fd, 1, -1))
			    == NULL) {
				afu->opened = 0;
				break;
			}
			size = (uint8_t) buffer[0];
			free(buffer);
			if ((buffer = get_bytes_silent(afu->fd, 8, -1))
			    == NULL) {
				afu->opened = 0;
				break;
			}
			addr = le64toh(*((uint64_t *) buffer));
			free(buffer);
			if ((buffer = get_bytes_silent(afu->fd, size, -1))
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
			if ((buffer = get_bytes_silent(afu->fd, 1, -1))
			    == NULL) {
				afu->opened = 0;
				break;
			}
			size = (uint8_t) buffer[0];
			free(buffer);
			if ((buffer = get_bytes_silent(afu->fd, 8, -1))
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
		pthread_mutex_lock(&(afu->lock));
	}

	afu->attached = 0;
	pthread_exit(NULL);
}

static int _pslse_connect(uint16_t *afu_map, int *fd)
{
	FILE *fp;
	uint8_t *buffer;
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
	buffer = (uint8_t*) calloc(1, MAX_LINE_CHARS);
	if(fgets((char*) buffer, MAX_LINE_CHARS-1, fp) == NULL) {
		perror("fgets:pslse_server.dat");
		fclose(fp);
		free(buffer);
		goto connect_fail;
	}
	fclose(fp);
	host = (char*) buffer;
	port_str = strchr((char*) buffer, ':');
	*port_str = '\0';
	port_str++;
	if (!host || !port_str) {
		warn_msg("cxl_afu_open_dev:Invalid format in pslse_server.dat");
		free(buffer);
		goto connect_fail;
	}
	port = atoi(port_str);

	// Connect to PSLSE server
	if ((he = gethostbyname(host)) == NULL) {
		herror("gethostbyname");
		free(buffer);
		goto connect_fail;
	}
	memset(&ssadr, 0, sizeof(ssadr));
	memcpy(&ssadr.sin_addr, he->h_addr_list[0], he->h_length);
	ssadr.sin_family = AF_INET;
	ssadr.sin_port = htons(port);
	if ((*fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		perror("socket");
		free(buffer);
		goto connect_fail;
	}
	ssadr.sin_family = AF_INET;
	ssadr.sin_port = htons(port);
	if (connect(*fd, (struct sockaddr *)&ssadr, sizeof(ssadr)) < 0) {
		perror("connect");
		free(buffer);
		goto connect_fail;
	}
	buffer = (uint8_t*) calloc(1, MAX_LINE_CHARS);
	strcpy((char*) buffer, "PSLSE");
	buffer[5] = (uint8_t) PSLSE_VERSION;
	if (put_bytes_silent(*fd, 6, buffer, -1) != 6) {
		warn_msg("cxl_afu_open_dev:Failed to write to socket!");
		free(host);
		free(buffer);
		goto connect_fail;
	}
	free(buffer);
	if ((buffer = get_bytes_silent(*fd, 3, -1)) == NULL) {
		warn_msg("cxl_afu_open_dev:Socket failed open acknowledge");
		free(host);
		close(*fd);
		*fd = -1;
		goto connect_fail;
	}
	if (buffer[0] != (uint8_t) PSLSE_CONNECT) {
		warn_msg("cxl_afu_open_dev:PSLSE bad acknowledge");
		free(host);
		free(buffer);
		close(*fd);
		*fd = -1;
		goto connect_fail;
	}
	memcpy((char*) afu_map, (char*) &(buffer[1]), 2);
	*afu_map = (long) le16toh(*afu_map);
	free(buffer);
	printf("Connection to %s:%d\n", host, port);
	free(host);
	return 0;

connect_fail:
	errno = ENODEV;
	return -1;
}

static struct cxl_adapter_h * _new_adapter(uint16_t afu_map, uint16_t position)
{
	struct cxl_adapter_h *adapter;
	uint16_t mask = 0xf000;
	int id_num = 0;

	if (position == 0)
		return NULL;

	adapter = (struct cxl_adapter_h*)
		calloc(1, sizeof(struct cxl_adapter_h));
	while ((position & mask) == 0) {
		mask >>= 4;
		++id_num;
	}
	adapter->map = afu_map;
	adapter->position = position;
	adapter->mask = mask;
	adapter->id = calloc(6, sizeof(char));
	sprintf(adapter->id, "card%d", id_num);
	return adapter;
}

static struct cxl_afu_h * _new_afu(uint16_t afu_map, uint16_t position)
{
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
	afu = (struct cxl_afu_h*)
		calloc(1, sizeof(struct cxl_afu_h));
	if (afu == NULL) {
		errno = ENOMEM;
		return NULL;
	}
	afu->adapter = major;
	afu->map = afu_map;
	afu->position = position;
	afu->id = calloc(7, sizeof(char));
	sprintf(afu->id, "afu%d.%d", major, minor);
	return afu;
}

static void _release_afus(struct cxl_afu_h *afu)
{
	struct cxl_afu_h *last, *current;
	int adapter;

	if (afu==NULL)
		return;

	if (afu->_head->adapter == afu->adapter) {
		current = afu->_head;
	}
	current = afu->_head;
	while (current->adapter < afu->adapter) {
		last = current;
		current = current->_next;
	}
	adapter = afu->adapter;
	current = afu;
	while ((current != NULL) && (current->adapter == adapter)) {
		afu = current;
		current = current->_next;
		free(afu->id);
		free(afu);
	}
}

static void _release_adapters(struct cxl_adapter_h *adapter)
{
	struct cxl_adapter_h *current;

	_release_afus(adapter->afu_list);
	current = adapter;
	while (current != NULL) {
		adapter = current;
		current = current->_next;
		free(adapter->id);
		free(adapter);
	}
}

static struct cxl_afu_h * _pslse_open(int fd, uint16_t afu_map, uint8_t major,
				      uint8_t minor, char afu_type)
{
	struct cxl_afu_h *afu;
	uint8_t *buffer;
	uint16_t position, query16;
	uint8_t dbg_id, query;
	size_t query_size;

	dbg_id = (major << 4) | minor;
	position = 0x8000;
	position >>= 4*major;
	position >>= minor;
	if ((afu_map & position) != position) {
		warn_msg("cxl_afu_open_dev:AFU not in system");
		close(fd);
		errno = ENODEV;
		return NULL;
	}

	// Create struct for AFU
	afu = _new_afu(afu_map, position);
	if (afu == NULL)
		return NULL;

	buffer = (uint8_t*) calloc(1, MAX_LINE_CHARS);
	buffer[0] = (uint8_t) PSLSE_OPEN;
	buffer[1] = dbg_id;
	buffer[2] = afu_type;
	afu->fd = fd;
	if (put_bytes_silent(afu->fd, 3, buffer, -1) != 3) {
		warn_msg("cxl_afu_open_dev:Failed to write to socket");
		free(buffer);
		goto open_fail;
	}
	free(buffer);
	if ((buffer = get_bytes_silent(afu->fd, 2, -1)) == NULL) {
		warn_msg("cxl_afu_open_dev:Socket failed open acknowledge");
		close(afu->fd);
		goto open_fail;
	}
	if (buffer[0] != (uint8_t) PSLSE_OPEN) {
		warn_msg("cxl_afu_open_dev:bad OPEN acknowledge");
		free(buffer);
		close(afu->fd);
		goto open_fail;
	}
	afu->context = buffer[1];
	free(buffer);
	query = PSLSE_QUERY;
	if (put_bytes_silent(afu->fd, 1, &query, -1) != 1) {
		warn_msg("cxl_afu_open_dev:Failed to write to socket!");
		goto open_fail;
	}
	query_size = sizeof(uint8_t)+sizeof(uint16_t);
	if ((buffer = get_bytes_silent(afu->fd, query_size, -1)) == NULL) {
		warn_msg("cxl_afu_open_dev:Socket failed context retrieve");
		close(afu->fd);
		goto open_fail;
	}
	if (buffer[0] != (uint8_t) PSLSE_QUERY) {
		warn_msg("cxl_afu_open_dev:Bad QUERY acknowledge");
		free(buffer);
		close(afu->fd);
		goto open_fail;
	}
	memcpy((char*) &query16, (char*) &(buffer[1]), 2);
	free(buffer);
	afu->_head = afu;
	afu->irqs_min = (long) le16toh(query16);
	afu->opened = 1;
	afu->api_version = 1;
	afu->api_version_compatible = 1;
	pthread_mutex_init(&(afu->lock), NULL);
	if (pthread_create(&(afu->thread), NULL, _psl_loop, afu)) {
		perror("pthread_create");
		close(afu->fd);
		goto open_fail;
	}
	afu->adapter = major;
	afu->id = (char *) malloc(7);
	sprintf(afu->id, "afu%d.%d", major, minor);

	return afu;

open_fail:
	free(afu);
	errno = ENODEV;
	return NULL;
}

struct cxl_adapter_h * cxl_adapter_next(struct cxl_adapter_h *adapter)
{
	struct cxl_adapter_h *head;
	uint16_t afu_map, afu_mask;
	int fd;
	uint8_t rc = PSLSE_DETACH;

	// First adapter
	if (adapter == NULL) {
		// Query PSLSE
		if (_pslse_connect(&afu_map, &fd) < 0)
			return NULL;
		// Disconnect from PSLSE
		if (put_bytes_silent(fd, 1, &rc, -1) != 1)
			return NULL;
		// No devices?
		assert (afu_map != 0);
		afu_mask = 0x8000;
		// Find first AFU and return struct for it
		while ((afu_map & afu_mask) != afu_mask)
			afu_mask >>= 1;
		head = _new_adapter(afu_map, afu_mask);
		head->_head = head;
		return head;
	}

	// Return next adapter if already set
	if (adapter->_next != NULL)
		return adapter->_next;

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
	adapter->_next = _new_adapter(afu_map, afu_mask);
	adapter->_next->_head = adapter->_head;
	return adapter->_next;
}

char * cxl_adapter_dev_name(struct cxl_adapter_h *adapter)
{
	if (adapter==NULL)
		return NULL;

	return adapter->id;
}

void cxl_adapter_free(struct cxl_adapter_h *adapter)
{
	struct cxl_adapter_h *head, *current;

	if (adapter==NULL)
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
	free(adapter->id);
	free(adapter);
}

struct cxl_afu_h * cxl_adapter_afu_next(struct cxl_adapter_h *adapter, struct cxl_afu_h *afu)
{
	struct cxl_afu_h *head;
	uint16_t afu_map, afu_mask;

	if (adapter==NULL)
		return NULL;

	afu_mask = adapter->position;
	afu_map = adapter->map;

	// First afu
	if (afu == NULL) {
		// No devices?
		assert (afu_map != 0);
		// Find first AFU and return struct for it
		afu_mask = adapter->mask & 0x8888;
		while ((afu_map & afu_mask) != afu_mask)
			afu_mask >>= 1;
		head = _new_afu(afu_map, afu_mask);
		head->_head = head;
		if (head != NULL)
			head->_head = head;
		return head;
	}

	// Return next afu if already set
	if (afu->_next != NULL)
		return afu->_next;

	// Find next afu on this adapter
	afu_mask = afu->position >> 1;
	afu_map = afu->map;
	while (((afu_mask & adapter->mask)!=0) && ((afu_mask & afu->map)==0))
		afu_mask >>= 1;

	// No more AFUs on this adapter
	if ((afu_mask & adapter->mask)==0) {
		_release_afus(adapter->afu_list);
		return NULL;
	}

	// Update pointers and return next afu
	afu->_next = _new_afu(afu_map, afu_mask);
	afu->_next->_head = afu->_head;
	return afu->_next;
}

struct cxl_afu_h * cxl_afu_next(struct cxl_afu_h *afu)
{
	struct cxl_afu_h *head;
	uint16_t afu_map, afu_mask;
	int fd;
	uint8_t rc = PSLSE_DETACH;

	// First afu
	if (afu == NULL) {
		// Query PSLSE
		if (_pslse_connect(&afu_map, &fd) < 0)
			return NULL;
		// Disconnect from PSLSE
		if (put_bytes_silent(fd, 1, &rc, -1) != 1)
			return NULL;
		// No devices?
		assert (afu_map != 0);
		afu_mask = 0x8000;
		// Find first AFU and return struct for it
		while ((afu_map & afu_mask) != afu_mask)
			afu_mask >>= 1;
		head = _new_afu(afu_map, afu_mask);
		head->_head = head;
		return head;
	}

	// Return next afu if already set
	if (afu->_next != NULL)
		return afu->_next;

	// Find next afu
	afu_mask = afu->position;
	afu_map = afu->map;
	afu_mask >>= 1;
	while ((afu_mask != 0) && ((afu_mask & afu_map) == 0))
		afu_mask >>= 1;

	// No more AFUs
	if (afu_mask == 0) {
		_release_afus(afu->_head);
		return NULL;
	}

	// Update pointers and return next afu
	afu->_next = _new_afu(afu_map, afu_mask);
	afu->_next->_head = afu->_head;
	return afu->_next;
}

char * cxl_afu_dev_name(struct cxl_afu_h *afu)
{
	return afu->id;
}

struct cxl_afu_h * cxl_afu_open_dev(char *path)
{
	uint16_t afu_map;
	uint8_t major, minor;
	char *afu_id;
	char afu_type;
	int fd;

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

	return _pslse_open(fd, afu_map, major, minor, afu_type);
}

struct cxl_afu_h * cxl_afu_open_h(struct cxl_afu_h *afu, enum cxl_views view)
{
	uint8_t major, minor;
	uint16_t mask;
	char afu_type;

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
	return _pslse_open(afu->fd, afu->map, major, minor, afu_type);
}

void cxl_afu_free(struct cxl_afu_h *afu) {
	uint8_t buffer;
	int rc;

	if (!afu->opened)
		goto free_done;

	DPRINTF("AFU FREE\n");
	buffer = PSLSE_DETACH;
	pthread_mutex_lock(&(afu->lock));
	rc = put_bytes_silent(afu->fd, 1, &buffer, -1);
	pthread_mutex_unlock(&(afu->lock));
	if (rc==1) {
		while (afu->attached)	/*infinite loop*/
			_delay_1ms();
	}
	pthread_mutex_lock(&(afu->lock));
	close(afu->fd);
	afu->opened = 0;
	if (afu->id != NULL)
		free(afu->id);
	pthread_mutex_unlock(&(afu->lock));
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
		warn_msg("cxl_afu_attach: Must open AFU first");
		errno = ENODEV;
		return -1;
	}

	if (afu->attached) {
		warn_msg("cxl_afu_attach: AFU already attached");
		errno = ENODEV;
		return -1;
	}

	buffer = (uint8_t*) calloc(1, MAX_LINE_CHARS);
	buffer[0] = PSLSE_ATTACH;
	wed_ptr = (uint64_t *) &(buffer[1]);
	*wed_ptr = htole64(wed);
	buffer[9] = '\0';
	pthread_mutex_lock(&(afu->lock));
	if (put_bytes_silent(afu->fd, 9, buffer, -1) != 9) {
		warn_msg("cxl_afu_attach: Socket fail on attach");
		afu->opened = 0;
		errno = ENODEV;
		pthread_mutex_unlock(&(afu->lock));
		return -1;
	}
	free(buffer);
	buffer = get_bytes_silent(afu->fd, 1, -1);
	while ((buffer != NULL) && (buffer[0] == '\0')) {
		free(buffer);
		buffer = get_bytes_silent(afu->fd, 1, -1);
	}
	if (buffer == NULL) {
		warn_msg("cxl_afu_attach: Socket fail on attach acknowledge");
		afu->opened = 0;
		errno = ENODEV;
		pthread_mutex_unlock(&(afu->lock));
		return -1;
	}
	if (buffer[0]!=(uint8_t) PSLSE_ATTACH) {
		warn_msg("cxl_afu_attach: Bad attach acknowledge");
		afu->opened = 0;
		free(buffer);
		errno = ENODEV;
		pthread_mutex_unlock(&(afu->lock));
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

	if (!afu->attached) {
		printf("cxl_mmio_map: Must attach first!\n");
		goto map_fail;
	}

	if (flags & ~(CXL_MMIO_FLAGS)) {
		printf("cxl_mmio_map: Invalid flags!\n");
		goto map_fail;
	}

	buffer[0] = PSLSE_MMIO_MAP;
	flags_ptr = (uint32_t *) &(buffer[1]);
	*flags_ptr = htole32(flags);
	if (put_bytes_silent(afu->fd, 5, buffer, -1) != 5) {
		perror("write");
		close(afu->fd);
		afu->opened = 0;
	}
	afu->mmio_pending = PSLSE_MMIO_MAP;
	pthread_mutex_unlock(&(afu->lock));
	while (afu->mmio_pending == PSLSE_MMIO_MAP)
		_delay_1ms();

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
	if (put_bytes_silent(afu->fd, 13, buffer, -1) != 13) {
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
	if (put_bytes_silent(afu->fd, 5, buffer, -1) != 5) {
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
	if (put_bytes_silent(afu->fd, 9, buffer, -1) != 9) {
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
	if (put_bytes_silent(afu->fd, 5, buffer, -1) != 5) {
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

