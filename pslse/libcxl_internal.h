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

#ifndef _LIBCXL_INTERNAL_H
#define _LIBCXL_INTERNAL_H

#include <sys/types.h>
#include <dirent.h>

struct cxl_adapter_h {
	DIR *enum_dir;
	struct dirent *enum_ent;
	char *sysfs_path;
};

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
	volatile __u32 mmio_flags;
	volatile int started;
	volatile size_t attached;
	volatile size_t mmio_size;
	volatile struct afu_descriptor desc;
};

#endif
