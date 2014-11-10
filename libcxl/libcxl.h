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

#ifndef _LIBCXL_H
#define _LIBCXL_H

#include <linux/types.h>
#include <misc/cxl.h>
#include <stdbool.h>
#include <stdint.h>

/*
 * This is a very early library to simplify userspace code accessing a CXL
 * device.
 *
 * Currently there are only a couple of functions here - more is on the way.
 *
 * Suggestions to improve the library, simplify it's usage, add additional
 * functionality, etc. are welcome
 */

#define CXL_SYSFS_CLASS "/sys/class/cxl"
#define CXL_DEV_DIR "/dev/cxl"

#define CXL_MMIO_FLAGS_AFU_BIG_ENDIAN		0x1
#define CXL_MMIO_FLAGS_AFU_LITTLE_ENDIAN	0x2
#define CXL_MMIO_FLAGS_AFU_HOST_ENDIAN		0x3

/*
 * Opaque types
 */
struct cxl_adapter_h;
struct cxl_afu_h;

/*
 * Adapter Enumeration
 *
 * Repeatedly call cxl_adapter_next() (or use the cxl_for_each_adapter macro)
 * to enumerate the available CXL adapters.
 *
 * cxl_adapter_next() will implicitly free used buffers if it is called on the
 * last adapter, or cxl_adapter_free() can be called explicitly.
 */
struct cxl_adapter_h * cxl_adapter_next(struct cxl_adapter_h *adapter);
char * cxl_adapter_devname(struct cxl_adapter_h *adapter);
void cxl_adapter_free(struct cxl_adapter_h *adapter);
#define cxl_for_each_adapter(adapter) \
	for (adapter = cxl_adapter_next(NULL); adapter; adapter = cxl_adapter_next(adapter))

/*
 * AFU Enumeration
 *
 * Repeatedly call cxl_adapter_afu_next() (or use the
 * cxl_for_each_adapter_afu macro) to enumerate AFUs on a specific CXL
 * adapter, or use cxl_afu_next() or cxl_for_each_afu to enumerate AFUs over
 * all CXL adapters in the system.
 *
 * For instance, if you just want to find any AFU attached to the system but
 * don't particularly care which one, just do:
 * struct cxl_afu_h *afu_h = cxl_afu_next(NULL);
 *
 * cxl_[adapter]_afu_next() will implicitly free used buffers if it is called
 * on the last AFU, or cxl_afu_free() can be called explicitly.
 */
struct cxl_afu_h * cxl_adapter_afu_next(struct cxl_adapter_h *adapter, struct cxl_afu_h *afu);
struct cxl_afu_h * cxl_afu_next(struct cxl_afu_h *afu);
char * cxl_afu_devname(struct cxl_afu_h *afu);
#define cxl_for_each_adapter_afu(adapter, afu) \
	for (afu = cxl_adapter_afu_next(adapter, NULL); afu; afu = cxl_adapter_afu_next(NULL, afu))
#define cxl_for_each_afu(afu) \
	for (afu = cxl_afu_next(NULL); afu; afu = cxl_afu_next(afu))


/*
 * Open AFU - either by path, by AFU being enumerated, or tie into an AFU file
 * descriptor that has already been opened. The AFU file descriptor will be
 * closed by cxl_afu_free() regardless of how it was opened.
 */
struct cxl_afu_h * cxl_afu_open_dev(char *path);
struct cxl_afu_h * cxl_afu_open_h(struct cxl_afu_h *afu, char *kind);
struct cxl_afu_h * cxl_afu_fd_to_h(int fd);
void cxl_afu_free(struct cxl_afu_h *afu);

/*
 * Attach AFU context to this process
 */
int cxl_afu_attach_full(struct cxl_afu_h *afu, __u64 wed, __u16 num_interrupts,
			__u64 amr);
int cxl_afu_attach(struct cxl_afu_h *afu, __u64 wed);

/*
 * Get AFU process element
 */
int cxl_afu_get_process_element(struct cxl_afu_h *afu);

/*
 * Returns the file descriptor for the open AFU to use with event loops.
 * Returns -1 if the AFU is not open.
 */
int cxl_afu_fd(struct cxl_afu_h *afu);

/*
 * TODO: All in one function - opens an AFU, verifies the operating mode and
 * attaches the context.
 * int cxl_afu_open_and_attach(struct cxl_afu_h *afu, mode)
 */

/*
 * sysfs helpers
 */

/*
 * NOTE: On success, this function automatically allocates the returned
 * buffer, which must be freed by the caller (much like asprintf).
 */
int cxl_afu_sysfs_pci(char **pathp, struct cxl_afu_h *afu);

/* Flags for cxl_get/set_mode and cxl_get_modes_supported */
#define CXL_MODE_DEDICATED   0x1
#define CXL_MODE_DIRECTED    0x2
#define CXL_MODE_TIME_SLICED 0x4

/* Values for cxl_get/set_prefault_mode */
enum cxl_prefault_mode {
	CXL_PREFAULT_MODE_NONE = 0,
	CXL_PREFAULT_MODE_WED,
	CXL_PREFAULT_MODE_ALL,
};

/* Values for cxl_get_image_loaded */
enum cxl_image {
	CXL_IMAGE_FACTORY = 0,
	CXL_IMAGE_USER,
};

/*
 * Get/set attribute values.
 * Return 0 on succes, -1 on error.
 */
int cxl_get_api_version(char* devname, long *valp);
int cxl_get_api_version_compatible(char* devname, long *valp);
int cxl_get_irqs_max(char* devname, long *valp);
int cxl_set_irqs_max(char* devname, long value);
int cxl_get_irqs_min(char* devname, long *valp);
int cxl_get_mmio_size(char* devname, long *valp);
int cxl_get_mode(char* devname, long *valp);
int cxl_set_mode(char* devname, long value);
int cxl_get_modes_supported(char* devname, long *valp);
int cxl_get_prefault_mode(char* devname, enum cxl_prefault_mode *valp);
int cxl_set_prefault_mode(char* devname, enum cxl_prefault_mode value);
int cxl_get_dev(char* devname, long *majorp, long *minorp);
int cxl_get_pp_mmio_len(char* devname, long *valp);
int cxl_get_pp_mmio_off(char* devname, long *valp);
int cxl_get_base_image(char* devname, long *valp);
int cxl_get_caia_version(char* devname, long *majorp, long *minorp);
int cxl_get_image_loaded(char* devname, enum cxl_image *valp);
int cxl_get_psl_revision(char* devname, long *valp);

/*
 * Events
 */
bool cxl_pending_event(struct cxl_afu_h *afu);
int cxl_read_event(struct cxl_afu_h *afu, struct cxl_event *event);
int cxl_read_expected_event(struct cxl_afu_h *afu, struct cxl_event *event,
			    __u32 type, __u16 irq);

/*
 * fprint wrappers to print out CXL events - useful for debugging.
 * fprint_cxl_event will select the appropriate implementation based on the
 * event type and fprint_cxl_unknown_event will print out a hex dump of the
 * raw event.
 */
int fprint_cxl_event(FILE *stream, struct cxl_event *event);
int fprint_cxl_unknown_event(FILE *stream, struct cxl_event *event);

/* AFU MMIO functions */

int cxl_mmio_map(struct cxl_afu_h *afu, __u32 flags);
int cxl_mmio_unmap(struct cxl_afu_h *afu);

/* WARNING: Use of cxl_mmio_ptr not supported for PSL Simulation Engine.
 * It is recommended that this function not be used but use the following MMIO
 * read/write functions instead. */
//void *cxl_mmio_ptr(struct cxl_afu_h *afu);

void cxl_mmio_write64(struct cxl_afu_h *afu, uint64_t offset, uint64_t data);
uint64_t cxl_mmio_read64(struct cxl_afu_h *afu, uint64_t offset);
void cxl_mmio_write32(struct cxl_afu_h *afu, uint64_t offset, uint32_t data);
uint32_t cxl_mmio_read32(struct cxl_afu_h *afu, uint64_t offset);

#endif
