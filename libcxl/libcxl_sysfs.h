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

#ifndef _LIBCXL_SYSFS_H
#define _LIBCXL_SYSFS_H

#include "libcxl.h"

enum cxl_sysfs_attr_type {
	/* AFU */
	AFU_API_VERSION = 0,
	AFU_API_VERSION_COMPATIBLE,
	AFU_IRQS_MAX,
	AFU_IRQS_MIN,
	AFU_MMIO_SIZE,
	AFU_MODE,
	AFU_MODES_SUPPORTED,
	AFU_PREFAULT_MODE,

	/* AFU Master */
	AFU_MASTER_MMIO_SIZE,

	/* AFU Master or Slave */
	AFU_DEV,
	AFU_PP_MMIO_LEN,
	AFU_PP_MMIO_OFF,
	AFU_UEVENT,

	/* Card */
	CARD_BASE_IMAGE,
	CARD_CAIA_VERSION,
	CARD_IMAGE_LOADED,
	CARD_PSL_REVISION,
	CARD_RESET_IMAGE_SELECT,
	CARD_RESET_LOADS_IMAGE,
};

typedef enum cxl_sysfs_attr_type cxl_sysfs_attr;

struct cxl_sysfs_entry_type {
	char *name;
	int (*scan_func)(char *attr_str, long *major, long *minor);
	int expected_num;
};

typedef struct cxl_sysfs_entry_type cxl_sysfs_entry;

/* Return flags for AFU_MODE and AFU_MODES_SUPPORTED */
#define CXL_MODE_DEDICATED   0x1
#define CXL_MODE_DIRECTED    0x2
#define CXL_MODE_TIME_SLICED 0x4

/* Return values for AFU_PREFAULT_MODE */
enum cxl_afu_prefault_modes {
	CXL_PREFAULT_MODE_NONE,
	CXL_PREFAULT_MODE_WED,
	CXL_PREFAULT_MODE_ALL,
};

/* Return values for CARD_IMAGE_LOADED and CARD_RESET_IMAGE_SELECT */
enum cxl_card_image {
	CXL_IMAGE_FACTORY,
	CXL_IMAGE_USER,
};
#endif
