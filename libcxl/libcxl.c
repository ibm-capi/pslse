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

#define _GNU_SOURCE /* For asprintf */
#define _BSD_SOURCE
#define __STDC_FORMAT_MACROS

#include <inttypes.h>
#include <assert.h>
#include <unistd.h>
#include <dirent.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <fcntl.h>
#include <regex.h>

#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "libcxl.h"


#undef DEBUG

#ifdef DEBUG
#define _s1(x) #x
#define _s(x) _s1(x)
#define pr_devel(...) \
	fprintf(stderr, _s(__FILE__) ":" _s(__LINE__) ": " __VA_ARGS__ );
#define pr_here() \
	pr_devel("<-- DEBUG TRACE -->\n");
#else
#define pr_devel(...) do { } while (0);
#define pr_here() do { } while (0);
#endif

#define CXL_EVENT_READ_FAIL 0xffff

struct cxl_adapter_h {
	DIR *enum_dir;
	struct dirent *enum_ent;
};

struct cxl_afu_h {
	struct cxl_adapter_h *adapter; /* Only used if allocated by us */
	DIR *enum_dir;
	int process_element;
	struct dirent *enum_ent;
	struct cxl_event *event_buf;		/* Event buffer storage */
	struct cxl_event *event_buf_first;	/* First event to read */
	struct cxl_event *event_buf_end;	/* End of events */
	char *dirpath;
	char *devname;
	int fd;
	int flags;
	void *ps_addr;
	size_t ps_size;
};


static struct cxl_adapter_h * malloc_adapter(void)
{
	struct cxl_adapter_h *adapter;

	if (!(adapter = malloc(sizeof(struct cxl_adapter_h))))
		return NULL;

	memset(adapter, 0, sizeof(struct cxl_adapter_h));

	return adapter;
}

char * cxl_adapter_devname(struct cxl_adapter_h *adapter)
{
	/* FIXME: Work if not enumerating */
	return adapter->enum_ent->d_name;
}

static struct cxl_afu_h * malloc_afu(void)
{
	struct cxl_afu_h *afu;

	if (!(afu = malloc(sizeof(struct cxl_afu_h))))
		return NULL;

	memset(afu, 0, sizeof(struct cxl_afu_h));
	afu->fd = -1;
	afu->process_element = -1;

	return afu;
}

char * cxl_afu_devname(struct cxl_afu_h *afu)
{
	if (afu->enum_ent)
		return afu->enum_ent->d_name;
	return afu->devname;
}

int cxl_afu_fd(struct cxl_afu_h *afu)
{
	return afu->fd;
}


/*
 * Adapter Enumeration
 */

static int is_cxl_adapter_filename(char *name)
{
	int rc;
	regex_t preg;

	if (*name != 'c')
		return 0;

	if (regcomp(&preg, "^card[0-9]\\+$", REG_NOSUB))
		return 0;
	rc = (regexec(&preg, name, 0, NULL, 0) != REG_NOMATCH);

	regfree(&preg);
	return rc;
}

static int is_cxl_afu_filename(char *name)
{
	int rc;
	regex_t preg;

	if (*name != 'a')
		return 0;

	if (regcomp(&preg, "^afu[0-9]\\+\\.[0-9]\\+$", REG_NOSUB))
		return 0;
	rc = (regexec(&preg, name, 0, NULL, 0) != REG_NOMATCH);

	regfree(&preg);
	return rc;
}

/* TODO: Refactor common code with cxl_adapter_afu_next() */
struct cxl_adapter_h * cxl_adapter_next(struct cxl_adapter_h *adapter)
{
	int saved_errno;

	if (adapter == NULL) {
		if (!(adapter = malloc_adapter()))
			return NULL;
		memset(adapter, 0, sizeof(struct cxl_adapter_h));
		if (!(adapter->enum_dir = opendir(CXL_SYSFS_CLASS)))
			goto end;
	}
	saved_errno = errno;
	errno = 0;
	do {
		if (!(adapter->enum_ent = readdir(adapter->enum_dir))) {
			if (errno == 0)
				errno = saved_errno;
			goto end;
		}
	} while (!is_cxl_adapter_filename(adapter->enum_ent->d_name));
	return adapter;

end:
	cxl_adapter_free(adapter);
	return NULL;
}

void cxl_adapter_free(struct cxl_adapter_h *adapter)
{
	if (!adapter)
		return;
	if (adapter->enum_dir)
		closedir(adapter->enum_dir);
	free(adapter);
}

/*
 * AFU Enumeration
 */

static void _cxl_afu_free(struct cxl_afu_h *afu, int free_adapter)
{
	if (!afu)
		return;
	if (afu->enum_dir)
		closedir(afu->enum_dir);
	if (afu->dirpath)
		free(afu->dirpath);	/* This also frees afu->devname. */
	if (free_adapter && afu->adapter)
		cxl_adapter_free(afu->adapter);
	if (afu->fd != -1)
		close(afu->fd);
	free(afu);
}

void cxl_afu_free(struct cxl_afu_h *afu)
{
	return _cxl_afu_free(afu, 1);
}


/* TODO: Refactor common code with cxl_adapter_next() */
struct cxl_afu_h *
cxl_adapter_afu_next(struct cxl_adapter_h *adapter, struct cxl_afu_h *afu)
{
	int saved_errno;

	if (afu == NULL) {
		assert(adapter);
		if (!(afu = malloc_afu()))
			return NULL;
		if (asprintf(&afu->dirpath, CXL_SYSFS_CLASS"/%s",
			     cxl_adapter_devname(adapter)) == -1)
			goto end;
		if (!(afu->enum_dir = opendir(afu->dirpath)))
			goto err_free;
	}
	saved_errno = errno;
	errno = 0;
	do {
		if (!(afu->enum_ent = readdir(afu->enum_dir))) {
			if (errno == 0)
				errno = saved_errno;
			goto end;
		}
	} while (!is_cxl_afu_filename(afu->enum_ent->d_name));
	return afu;
err_free:
	free(afu->dirpath);
	afu->dirpath = NULL;
end:
	_cxl_afu_free(afu, 0);
	return NULL;
}

struct cxl_afu_h * cxl_afu_next(struct cxl_afu_h *afu)
{
	struct cxl_adapter_h *adapter = NULL;

	if (afu)
		adapter = afu->adapter;
	else if (!(adapter = cxl_adapter_next(NULL)))
		return NULL;

	do {
		if ((afu = cxl_adapter_afu_next(adapter, afu)))
			afu->adapter = adapter;
		else
			adapter = cxl_adapter_next(adapter);
	} while (adapter && !afu);

	return afu;
}

static int cxl_sysfs_fd(char **bufp, struct cxl_afu_h *afu)
{
	int fd = cxl_afu_fd(afu);
	struct stat sb;

	if (fstat(fd, &sb) < 0)
		return -1;
	if (!S_ISCHR(sb.st_mode))
		return -1;
	return asprintf(bufp, "/sys/dev/char/%i:%i", major(sb.st_rdev), minor(sb.st_rdev));
}

static int cxl_sysfs(char **bufp, struct cxl_afu_h *afu)
{
	if (afu->fd >= 0)
		return cxl_sysfs_fd(bufp, afu);

	return asprintf(bufp, "%s/%s", afu->dirpath, cxl_afu_devname(afu));
}

#if 0
static int cxl_sysfs_afu(char **path, struct cxl_afu_h *afu)
{
}

static int cxl_sysfs_adapter(char **path, struct cxl_adapter_h *adapter)
{
}
#endif

static int sysfs_subsystem(char **bufp, const char *path)
{
	char *subsystem_path, *name, *buf;
	char subsystem_link[256];
	int len;
	int rc = -1;

	if ((asprintf(&subsystem_path, "%s/subsystem", path)) == -1)
		return -1;

	/* lstat returns sb.st_size == 0 for symlinks in /sys (WTF WHY???), so
	 * we use a static buffer since we have NFI how large to allocate */
	if ((len = readlink(subsystem_path, subsystem_link, sizeof(subsystem_link) - 1)) == -1)
		goto out;
	if (len >= sizeof(subsystem_link) - 1)
		goto out;
	subsystem_link[len] = '\0';

	name = basename(subsystem_link);
	if (!(buf = malloc(strlen(name) + 1)))
		goto out;

	strcpy(buf, name);
	*bufp = buf;
	rc = 0;

out:
	free(subsystem_path);
	return rc;
}

static int normalize_afu_path(struct cxl_afu_h *afu, char *path)
{
	char *tmp;

	/* Allocate dirpath and make path absolute. */
	if (*path == '/') {
		afu->dirpath = strdup(path);
		if (afu->dirpath == NULL)
			return -1;
	} else {
		tmp = getcwd(NULL, 0);
		if (asprintf(&afu->dirpath, "%s/%s", tmp, path) == -1)
			goto err;
		free(tmp);
	}
	/* Split dirpath between dirpath and devname */
        tmp = strrchr(afu->dirpath, '/');
	*tmp = '\0';
	afu->devname = tmp + 1;
	return 0;

err:
	free(tmp);
	return -1;
}

int cxl_afu_sysfs_pci(char **pathp, struct cxl_afu_h *afu)
{
	char *path, *new_path, *subsys;
	struct stat sb;
	if ((cxl_sysfs(&path, afu)) < 0)
		return -1;

	do {
		if ((asprintf(&new_path, "%s/device", path)) == -1)
			goto err;
		free(path);
		path = new_path;

		if ((sysfs_subsystem(&subsys, path)) == -1) {
			if (errno == ENOENT)
				continue;
			goto err;
		}
		if (!(strcmp(subsys, "pci"))) {
			free(subsys);
			*pathp = path;
			return 0;
		}
		free(subsys);
	} while (stat(path, &sb) != -1);

err:
	free(path);
	return -1;
}

static int is_afu_dev(char *devname, long major, long minor)
{
	long sysfs_major, sysfs_minor;

	if (cxl_get_dev(devname, &sysfs_major, &sysfs_minor) < 0)
		return 0;
	return (major == sysfs_major && minor == sysfs_minor);
}

/* Open Functions */

static int open_afu_dev(struct cxl_afu_h *afu, char *path)
{
	struct stat sb;
	int fd;

	if ((fd = open(path, O_RDWR | O_CLOEXEC)) < 0)
		return fd;

	/* Verify that this is an AFU file we just opened */
	if (fstat(fd, &sb) < 0)
		goto err_close;
	if (!S_ISCHR(sb.st_mode))
		goto err_close;
	if (normalize_afu_path(afu, path) < 0)
		goto err_close;
	if (! is_afu_dev(afu->devname, major(sb.st_rdev), minor(sb.st_rdev)))
		goto err_close;
	afu->fd = fd;
	return 0;

err_close:
	close(fd);
	afu->fd = -1;
	errno = ENODEV;
	return -1;
}

static int major_minor_match(int dirfd, char *devname, int major, int minor)
{
	struct stat sb;

	if (*devname != 'a')
		return 0;
	if (fstatat(dirfd, devname, &sb, 0) == -1)
		return 0;
	if (!S_ISCHR(sb.st_mode))
		return 0;
	return major(sb.st_rdev) == major && minor(sb.st_rdev) == minor;
}

static char *find_dev_path(int major, int minor)
{
	int saved_errno;
	DIR *enum_dir;
	struct dirent *enum_ent;
	int fd;
	char *path = NULL;

	if ((enum_dir = opendir(CXL_DEV_DIR)) == NULL)
		return NULL;
	fd = dirfd(enum_dir);
	saved_errno = errno;
	errno = 0;
	do {
		if (!(enum_ent = readdir(enum_dir))) {
			if (errno == 0)
				errno = saved_errno;
			goto err_exit;
		}
	} while (!major_minor_match(fd, enum_ent->d_name, major, minor));

	if ((asprintf(&path, CXL_DEV_DIR"/%s", enum_ent->d_name)) == -1)
		goto err_exit;
	closedir(enum_dir);
	return path;

err_exit:
	closedir(enum_dir);
	return NULL;
}

int cxl_afu_get_process_element(struct cxl_afu_h *afu)
{
	int process_element;
	int rc;

	if (afu->process_element >= 0)
		/* return cached version */
		return afu->process_element;

	rc = ioctl(afu->fd, CXL_IOCTL_GET_PROCESS_ELEMENT, &process_element);
	if (rc < 0)
		return rc;
	afu->process_element = process_element;

	return process_element;
}

struct cxl_afu_h * cxl_afu_open_dev(char *path)
{
	struct cxl_afu_h *afu;

	if (!(afu = malloc_afu()))
		return NULL;

	if (open_afu_dev(afu, path) < 0)
		goto err;

	return afu;
err:
	cxl_afu_free(afu);
	return NULL;
}

static char *build_devname(char *devname, char *kind)
{
	char lastchar;
	char *newname;

	lastchar = *(devname + strlen(devname) - 1);
	if (lastchar != *kind) {
		switch (lastchar) {
		case 'd':
		case 'm':
		case 's':	/* modify last char */
			newname = strdup(devname);
			if (newname != NULL)
				*(newname + strlen(newname) - 1) = *kind;
			break;
		default:	/* append last char */
			asprintf(&newname, "%s%s", devname, kind);
		}
	} else
		newname = strdup(devname);
	return newname;
}

struct cxl_afu_h * cxl_afu_open_h(struct cxl_afu_h *afu, char *kind)
{
	char *devname;
	char *newname = NULL;
	char *path = NULL;
	struct cxl_afu_h *newafu = NULL;
	long sysfs_major, sysfs_minor;

	if ((devname = cxl_afu_devname(afu)) == NULL)
		return NULL;
	if ((newname = build_devname(devname, kind)) == NULL)
		return NULL;
	if (cxl_get_dev(newname, &sysfs_major, &sysfs_minor) < 0)
		goto err_exit;
	if (!(newafu = malloc_afu()))
		goto err_exit;
	if ((path = find_dev_path(sysfs_major, sysfs_minor)) == NULL)
		goto err_exit;
	if ((newafu->fd = open(path, O_RDWR | O_CLOEXEC)) < 0)
		goto err_exit;
	if (normalize_afu_path(newafu, path) < 0)
		goto err_exit;
	free(path);
	return newafu;

err_exit:
	if (path)
		free(path);
	if (newafu)
		free(newafu);
	if (newname)
		free(newname);
	errno = ENODEV;
	return NULL;
}

struct cxl_afu_h * cxl_afu_fd_to_h(int fd)
{
	struct cxl_afu_h *afu;
	struct stat sb;
	char *path = NULL;

	if (!(afu = malloc_afu()))
		return NULL;
	/* Verify that the passed in fd is an AFU fd */
	if (fstat(fd, &sb) < 0)
		goto err_exit;
	if (!S_ISCHR(sb.st_mode))
		goto err_exit;
	if (!(path = find_dev_path(major(sb.st_rdev), minor(sb.st_rdev))))
		goto err_exit;
	if (normalize_afu_path(afu, path) < 0)
		goto err_exit;
	free(path);
	afu->fd = fd;
	return afu;

err_exit:
	if (path)
		free(path);
	free(afu);
	errno = ENODEV;
	return NULL;
}

int cxl_afu_attach(struct cxl_afu_h *afu, __u64 wed)
{
	struct cxl_ioctl_start_work work;

	if (afu->fd < 0) {
		errno = EINVAL;
		return -1;
	}

	memset(&work, 0, sizeof(work));
	work.work_element_descriptor = wed;

	return ioctl(afu->fd, CXL_IOCTL_START_WORK, &work);
}

int cxl_afu_attach_full(struct cxl_afu_h *afu, __u64 wed, __u16 num_interrupts,
			__u64 amr)
{
	struct cxl_ioctl_start_work work;

	if (afu->fd < 0) {
		errno = EINVAL;
		return -1;
	}

	memset(&work, 0, sizeof(work));
	work.work_element_descriptor = wed;
	work.flags = CXL_START_WORK_NUM_IRQS | CXL_START_WORK_AMR;
	work.num_interrupts = num_interrupts;
	work.amr = amr;

	return ioctl(afu->fd, CXL_IOCTL_START_WORK, &work);
}

/*
 * Event description print helpers
 */

static int
fprint_cxl_afu_interrupt(FILE *stream, struct cxl_event_afu_interrupt *event)
{
	return fprintf(stream, "AFU Interrupt %i\n", event->irq);
}

static int
fprint_cxl_data_storage(FILE *stream, struct cxl_event_data_storage *event)
{
	return fprintf(stream, "AFU Invalid memory reference: 0x%"PRIx64"\n",
		       event->addr);
}

static int
fprint_cxl_afu_error(FILE *stream, struct cxl_event_afu_error *event)
{
	return fprintf(stream, "AFU Error: 0x%"PRIx64"\n", event->error);
}

static int hexdump(FILE *stream, __u8 *addr, ssize_t size)
{
	unsigned i, j, c = 0;

	for (i = 0; i < size; i += 4) {
		for (j = i; j < size && j < i + 4; j++)
			c += fprintf(stream, "%.2x", addr[j]);
		c += fprintf(stream, " ");
	}
	c += fprintf(stream, "\n");
	return c;
}

int
fprint_cxl_unknown_event(FILE *stream, struct cxl_event *event)
{
	int ret;
	ret = fprintf(stream, "CXL Unknown Event %i: ", event->header.type);
	if (ret < 0)
		return ret;
	ret += hexdump(stream, (__u8 *)event, event->header.size);
	return ret;
}

/*
 * Print a description of the given event to the file stream.
 */
int
fprint_cxl_event(FILE *stream, struct cxl_event *event)
{
	switch (event->header.type) {
		case CXL_EVENT_READ_FAIL:
			fprintf(stderr, "fprint_cxl_event: CXL Read failed\n");
			return -1;
		case CXL_EVENT_AFU_INTERRUPT:
			return fprint_cxl_afu_interrupt(stream, &event->irq);
		case CXL_EVENT_DATA_STORAGE:
			return fprint_cxl_data_storage(stream, &event->fault);
		case CXL_EVENT_AFU_ERROR:
			return fprint_cxl_afu_error(stream, &event->afu_error);
		default:
			return fprint_cxl_unknown_event(stream, event);
	}
}

static inline void poison(__u8 *ptr, ssize_t len)
{
	unsigned int toxin = 0xDEADBEEF;
	__u8 *end;

	for (end = ptr + len; ptr < end; ptr++)
		*ptr = (toxin >> (8 * (3 - ((uintptr_t)ptr % 4)))) & 0xff;
}

static inline int fetch_cached_event(struct cxl_afu_h *afu,
				     struct cxl_event *event)
{
	int size;

	/* Local events caches, let's send it out */
	size = afu->event_buf_first->header.size;
	memcpy(event, afu->event_buf_first, size);
	afu->event_buf_first = (struct cxl_event *)
		((char *)afu->event_buf_first + size);
	assert(afu->event_buf_first <= afu->event_buf_end);
	return 0;
}

bool cxl_pending_event(struct cxl_afu_h *afu)
{
	return (afu->event_buf_first != afu->event_buf_end);
}

int cxl_read_event(struct cxl_afu_h *afu, struct cxl_event *event)
{
	struct cxl_event *p;
	ssize_t size;

	/* Init buffer */
	if (!afu->event_buf) {
		p = malloc(CXL_READ_MIN_SIZE);
		if (!p) {
			errno = ENOMEM;
			return -1;
		}
		afu->event_buf = p;
		afu->event_buf_first = afu->event_buf;
		afu->event_buf_end = afu->event_buf;
	}

	/* Send buffered event */
	if (cxl_pending_event(afu))
		return fetch_cached_event(afu, event);

	if (afu->fd < 0) {
		errno = EINVAL;
		return -1;
	}

	/* Looks like we need to go read some data from the kernel */
	size = read(afu->fd, afu->event_buf, CXL_READ_MIN_SIZE);
	if (size <= 0) {
		poison((__u8 *)event, sizeof(*event));
		event->header.type = CXL_EVENT_READ_FAIL;
		event->header.size = 0;
		if (size < 0)
			return size;
		errno = ENODATA;
		return -1;
	}

	/* check for at least 1 event */
	assert(size >= afu->event_buf->header.size);

	afu->event_buf_first = afu->event_buf;
	afu->event_buf_end = (struct cxl_event *)
		((char *)afu->event_buf + size);

	return fetch_cached_event(afu, event);
}

/*
 * Read an event from the AFU when an event of type is expected. For AFU
 * interrupts, the expected AFU interrupt number may also be supplied (0 will
 * accept any AFU interrupt).
 *
 * Returns 0 if the read event was of the expected type and (if applicable)
 * AFU interrupt number. If the event did not match the type & interrupt
 * number, it returns -1.
 *
 * If the read() syscall failed for some reason (e.g. no event pending when
 * using non-blocking IO, etc) it will return -2 and errno will be set
 * appropriately.
 */
int cxl_read_expected_event(struct cxl_afu_h *afu, struct cxl_event *event,
			   __u32 type, __u16 irq)
{
	int rv;

	if ((rv = cxl_read_event(afu, event)) < 0)
		return rv;

#if 0
	printf("cxl_read_expected_event: Poisoning %li bytes from %p, event: %p, size: %li, rv: %i\n",
			size - rv, (void*)(((__u8 *)event) + rv), (void*)event, size, rv);
	hexdump(stderr, (__u8 *)event, size);
#endif

	if (event->header.type != type)
		return -1;

	if ((type == CXL_EVENT_AFU_INTERRUPT) && irq) {
		if (!(event->irq.irq == irq))
			return -1;
	}

	return 0;
}

/*
 * MMIO abstractions
 */

/* Map AFU Problem State Registers into memory */
int
cxl_mmio_map(struct cxl_afu_h *afu, __u32 flags)
{
	int fd = afu->fd;
	void *ps_addr;
	char *devname;
	struct cxl_afu_h *newafu = NULL;
	long sysfs_major, sysfs_minor;
	size_t size;

	if ((devname = cxl_afu_devname(afu)) == NULL)
		return -1;
	if (cxl_get_dev(devname, &sysfs_major, &sysfs_minor) < 0)
		return -1;
	if (cxl_get_mmio_size(devname, &size) < 0)
		return -1;

	ps_addr = mmap(NULL, size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
	if (ps_addr == MAP_FAILED)
		return -1;

	afu->ps_size = size;
	afu->flags = flags;
	afu->ps_addr = ps_addr;
	return 0;
}

/* Unmap AFU Problem State Registers from memory */
int
cxl_mmio_unmap(struct cxl_afu_h *afu)
{
	if (munmap(afu->ps_addr, afu->ps_size)) {
		perror("cxl_unmap_ps_registers");
		return -1;
	}

	afu->ps_addr = 0;
	afu->ps_size = 0;
	return 0;
}

/* WARNING: Use of cxl_mmio_ptr not supported for PSL Simulation Engine.
 * It is recommended that this function not be used but use the following MMIO
 * read/write functions instead. */
//void *cxl_mmio_ptr(struct cxl_afu_h *afu);

/* MMIO write, 64 bit */
void
cxl_mmio_write64(struct cxl_afu_h *afu, uint64_t offset, uint64_t data)
{
	if (afu->flags == CXL_MMIO_FLAGS_AFU_LITTLE_ENDIAN)
		data = htole64(data);
	else if (afu->flags == CXL_MMIO_FLAGS_AFU_BIG_ENDIAN)
		data = htobe64(data);
	void *offset2 = afu->ps_addr + (offset & ~0x1);
	__asm__ __volatile__("std%U0%X0 %1,%0" : "=m"(*(uint64_t *)offset2) : "r"(data));
}

/* MMIO read, 64 bit */
uint64_t
cxl_mmio_read64(struct cxl_afu_h *afu, uint64_t offset)
{
	uint64_t data;
	void *offset2 = afu->ps_addr + (offset & ~0x1);
	__asm__ __volatile__("ld%U1%X1 %0,%1" : "=r"(data) : "m"(*(uint64_t *)offset2));
	if (afu->flags == CXL_MMIO_FLAGS_AFU_LITTLE_ENDIAN)
		data = le64toh(data);
	else if (afu->flags == CXL_MMIO_FLAGS_AFU_BIG_ENDIAN)
		data = be64toh(data);
	return data;
}

/* MMIO write, 32 bit */
void
cxl_mmio_write32(struct cxl_afu_h *afu, uint64_t offset, uint32_t data)
{
	if (afu->flags == CXL_MMIO_FLAGS_AFU_LITTLE_ENDIAN)
		data = htole32(data);
	else if (afu->flags == CXL_MMIO_FLAGS_AFU_BIG_ENDIAN)
		data = htobe32(data);
	void *offset2 = afu->ps_addr + offset;
	__asm__ __volatile__("stw%U0%X0 %1,%0" : "=m"(*(uint32_t *)offset2) : "r"(data));
}

/* MMIO read, 32 bit */
uint32_t
cxl_mmio_read32(struct cxl_afu_h *afu, uint64_t offset)
{
	uint32_t data;
	void *offset2 = afu->ps_addr + offset;
	__asm__ __volatile__("lwz%U1%X1 %0,%1" : "=r"(data) : "m"(*(uint32_t *)offset2));
	if (afu->flags == CXL_MMIO_FLAGS_AFU_LITTLE_ENDIAN)
		data = le32toh(data);
	else if (afu->flags == CXL_MMIO_FLAGS_AFU_BIG_ENDIAN)
		data = be32toh(data);
	return data;
}
