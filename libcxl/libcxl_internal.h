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
#include <linux/types.h>
#include <poll.h>
#include <pthread.h>

struct cxl_afu_h {
	pthread_t thread;
	struct cxl_event *irq;
	struct cxl_event *dsi;
	struct cxl_event *first_event;
	int adapter;
	char *id;
	uint8_t context;
	uint16_t map;
	uint16_t position;
	uint8_t dbg_id;
	int fd;
	int opened;
	int attached;
	int mapped;
	int pipe;
	volatile int mmio_pending;
	uint64_t mmio_data;
	long irqs_max;
	long irqs_min;
	long mmio_size;
	long mode;
	long modes_supported;
	long mmio_len;
	long mmio_off;
	long prefault_mode;
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
