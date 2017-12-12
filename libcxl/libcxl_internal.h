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

#ifndef _LIBCXL_INTERNAL_H
#define _LIBCXL_INTERNAL_H

#include <dirent.h>
#include <inttypes.h>
#include <poll.h>
#include <pthread.h>

#define EVENT_QUEUE_MAX 3

enum libcxl_req_state {
	LIBCXL_REQ_IDLE,
	LIBCXL_REQ_REQUEST,
	LIBCXL_REQ_PENDING
};

struct int_req {
	volatile enum libcxl_req_state state;
	volatile uint16_t max;
};

struct open_req {
	volatile enum libcxl_req_state state;
	volatile uint8_t context;
};

struct attach_req {
	volatile enum libcxl_req_state state;
	volatile uint64_t wed;
};

struct mmio_req {
	volatile enum libcxl_req_state state;
	volatile uint8_t type;
	volatile uint32_t addr;
	uint64_t data;
};

struct cxl_afu_h {
	pthread_t thread;
	pthread_mutex_t event_lock;
	pthread_mutex_t mmio_lock;
        struct cxl_event **events;
	int adapter;
	char *id;
	uint16_t context;
	uint16_t map;
	uint16_t position;
	uint8_t dbg_id;
	int fd;
	int opened;
	int attached;
	int mapped;
	int pipe[2];
	long irqs_max;
	long irqs_min;
	long mode;
	long modes_supported;
	long mmio_len;
	long mmio_off;
	long prefault_mode;
        size_t eb_len;
	long cr_device;
	long cr_vendor;
	long cr_class;
	struct int_req int_req;
	struct open_req open;
	struct attach_req attach;
	struct mmio_req mmio;
	struct cxl_afu_h *_head;
	struct cxl_afu_h *_next;
	struct cxl_afu_h *_next_adapter;
};

struct cxl_adapter_h {
	DIR *enum_dir;
	struct dirent *enum_ent;
	char *sysfs_path;
	long caia_major;
	long caia_minor;
	long pslse_version;
	int fd;
	char *id;
	uint16_t map;
	uint16_t mask;
	uint16_t position;
	struct cxl_adapter_h *_head;
	struct cxl_adapter_h *_next;
	struct cxl_afu_h *afu_list;
};

#endif
