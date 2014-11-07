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

#define _GNU_SOURCE
#include <fcntl.h>
#include <misc/cxl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "libcxl.h"

enum cxl_sysfs_attr {
	/* AFU */
	API_VERSION = 0,
	API_VERSION_COMPATIBLE,
	IRQS_MAX,
	IRQS_MIN,
	MMIO_SIZE,
	MODE,
	MODES_SUPPORTED,
	PREFAULT_MODE,

	/* AFU Master or Slave */
	DEV,
	PP_MMIO_LEN,
	PP_MMIO_OFF,

	/* Card */
	BASE_IMAGE,
	CAIA_VERSION,
	IMAGE_LOADED,
	PSL_REVISION,
};

struct cxl_sysfs_entry {
	char *name;
	int (*scan_func)(char *attr_str, long *major, long *minor);
	int expected_num;
};

static int scan_int(char *attr_str, long *majorp, long *minorp);
static int scan_dev(char *attr_str, long *majorp, long *minorp);
static int scan_mode(char *attr_str, long *majorp, long *minorp);
static int scan_modes(char *attr_str, long *majorp, long *minorp);
static int scan_prefault_mode(char *attr_str, long *majorp, long *minorp);
static int scan_caia_version(char *attr_str, long *majorp, long *minorp);
static int scan_image(char *attr_str, long *majorp, long *minorp);

static struct cxl_sysfs_entry sysfs_entry[] = {
 { "api_version", scan_int, 1 },		/* API_VERSION */
 { "api_version_compatible", scan_int, 1 },	/* API_VERSION_COMPATIBLE */
 { "irqs_max", scan_int, 1 },			/* IRQS_MAX */
 { "irqs_min", scan_int, 1 },			/* IRQS_MIN */
 { "mmio_size", scan_int, 1 },			/* MMIO_SIZE */
 { "mode", scan_mode, 1 },			/* MODE */
 { "modes_supported", scan_modes, 1 },		/* MODES_SUPPORTED */
 { "prefault_mode", scan_prefault_mode, 1 },	/* PREFAULT_MODE */
 { "dev", scan_dev, 2 },			/* DEV */
 { "pp_mmio_len", scan_int, 1 },		/* PP_MMIO_LEN */
 { "pp_mmio_off", scan_int, 1 },		/* PP_MMIO_OFF */
 { "base_image", scan_int, 1 },			/* BASE_IMAGE */
 { "caia_version", scan_caia_version, 2 },	/* CAIA_VERSION */
 { "image_loaded", scan_image, 1 },		/* IMAGE_LOADED */
 { "psl_revision", scan_int, 1 },		/* PSL_REVISION */
};

#define LAST_ATTR PSL_REVISION
#define OUT_OF_RANGE(attr) ((attr) < 0 || (attr) > LAST_ATTR)

static int scan_int(char *attr_str, long *majorp, long *minorp)
{
	return sscanf(attr_str, "%ld", majorp);
}

static int scan_dev(char *attr_str, long *majorp, long *minorp)
{
	return sscanf(attr_str, "%ld:%ld", majorp, minorp);
}

static int scan_caia_version(char *attr_str, long *majorp, long *minorp)
{
	return sscanf(attr_str, "%ld.%ld", majorp, minorp);
}

static int scan_mode(char *attr_str, long *majorp, long *minorp)
{
	int count;
	char buf[18];

	if ((count = sscanf(attr_str, "%17s", buf)) != 1)
		return -1;
	if (!strcmp(buf, "dedicated_process")) {
		*majorp = CXL_MODE_DEDICATED;
		count = 0;
	} else if (!strcmp(buf, "afu_directed")) {
		*majorp = CXL_MODE_DIRECTED;
		count = 0;
	}
	return (count == 0);
}

static int scan_modes(char *attr_str, long *majorp, long *minorp)
{
	long val1, val2 = 0;
	char buf1[18], buf2[18];
	int rc;

	if ((rc = sscanf(attr_str, "%17s\n%17s", buf1, buf2)) <= 0)
		return -1;
	if (rc == 2 && scan_mode(buf2, &val2, NULL) != 1)
		return -1;
	if (scan_mode(buf1, &val1, NULL) != 1)
		return -1;
	*majorp = val1|val2;
	return 1;
}

static int scan_prefault_mode(char *attr_str, long *majorp, long *minorp)
{
	int count;
	char buf[24];
	if ((count = sscanf(attr_str, "%23s", buf)) != 1)
		return -1;
	if (!strcmp(buf, "none")) {
		*majorp = CXL_PREFAULT_MODE_NONE;
		count = 0;
	} else if (!strcmp(buf, "work_element_descriptor")) {
		*majorp = CXL_PREFAULT_MODE_WED;
		count = 0;
	} else if (!strcmp(buf, "all")) {
		*majorp = CXL_PREFAULT_MODE_ALL;
		count = 0;
	}
	return (count == 0);
}

static int scan_image(char *attr_str, long *majorp, long *minorp)
{
	int count;
	char buf[8];

	if ((count = sscanf(attr_str, "%7s", buf)) != 1)
		return -1;
	if (!strcmp(buf, "factory")) {
		*majorp = CXL_IMAGE_FACTORY;
		count = 0;
	} else if (!strcmp(buf, "user")) {
		*majorp = CXL_IMAGE_USER;
		count = 0;
	}
	return (count == 0);
}

static char *cxl_sysfs_attr_name(enum cxl_sysfs_attr attr) {
	if (OUT_OF_RANGE(attr))
		return NULL;
	return sysfs_entry[attr].name;
}

#define BUFLEN 256

static char *cxl_read_sysfs_str(char *devname, enum cxl_sysfs_attr attr)
{
	char *sysfs_path;
	char *attr_name;
	int fd, count;
	char buf[BUFLEN];

	if (devname == NULL)
		return NULL;
	attr_name = cxl_sysfs_attr_name(attr);
	if (attr_name == NULL)
		return NULL;
	asprintf(&sysfs_path, CXL_SYSFS_CLASS"/%s/%s", devname, attr_name);
	if (sysfs_path == NULL)
		return NULL;
	fd = open(sysfs_path, O_RDONLY);
	free(sysfs_path);
	if (fd == -1) {
		asprintf(&sysfs_path, CXL_SYSFS_CLASS"/%s/device/%s", devname,
			attr_name);
		if (sysfs_path == NULL)
			return NULL;
		fd = open(sysfs_path, O_RDONLY);
		free(sysfs_path);
		if (fd == -1)
			return NULL;
	}
	count = read(fd, buf, BUFLEN);
	close(fd);
	if (count == -1)
		return NULL;
	buf[count - 1] = '\0';
	return strdup(buf);
}

static int cxl_scan_sysfs_str(enum cxl_sysfs_attr attr, char *attr_str,
			      long *majorp, long *minorp)
{
	int (*scan_func)(char *attr_str, long *majorp, long *minorp);

	if (OUT_OF_RANGE(attr))
		return -1;
	scan_func = sysfs_entry[attr].scan_func;
	if (scan_func == NULL)
		return 0;
	return (*scan_func)(attr_str, majorp, minorp);
}

static int cxl_read_sysfs(char *devname, enum cxl_sysfs_attr attr, long *majorp,
		   long *minorp)
{
	char *buf;
	int expected, ret;

	if (devname == NULL)
		return -1;
	if (OUT_OF_RANGE(attr))
		return -1;
	if ((buf = cxl_read_sysfs_str(devname, attr)) == NULL)
		return -1;
	expected = sysfs_entry[attr].expected_num;
	ret = cxl_scan_sysfs_str(attr, buf, majorp, minorp);
	free(buf);
	return (ret == expected) ? 0 : -1;
}

int cxl_get_api_version(char* devname, long *valp)
{
	return cxl_read_sysfs(devname, API_VERSION, valp, NULL);
}

int cxl_get_api_version_compatible(char* devname, long *valp)
{
	return cxl_read_sysfs(devname, API_VERSION_COMPATIBLE, valp, NULL);
}

int cxl_get_irqs_max(char* devname, long *valp)
{
	return cxl_read_sysfs(devname, IRQS_MAX, valp, NULL);
}

int cxl_get_irqs_min(char* devname, long *valp)
{
	return cxl_read_sysfs(devname, IRQS_MIN, valp, NULL);
}

int cxl_get_mmio_size(char* devname, long *valp)
{
	return cxl_read_sysfs(devname, MMIO_SIZE, valp, NULL);
}

int cxl_get_mode(char* devname, long *valp)
{
	return cxl_read_sysfs(devname, MODE, valp, NULL);
}

int cxl_get_modes_supported(char* devname, long *valp)
{
	return cxl_read_sysfs(devname, MODES_SUPPORTED, valp, NULL);
}

int cxl_get_prefault_mode(char* devname, enum cxl_prefault_mode *valp)
{
	return cxl_read_sysfs(devname, PREFAULT_MODE, (long *)valp, NULL);
}

int cxl_get_dev(char* devname, long *majorp, long *minorp)
{
	return cxl_read_sysfs(devname, DEV, majorp, minorp);
}

int cxl_get_pp_mmio_len(char* devname, long *valp)
{
	return cxl_read_sysfs(devname, PP_MMIO_LEN, valp, NULL);
}

int cxl_get_pp_mmio_off(char* devname, long *valp)
{
	return cxl_read_sysfs(devname, PP_MMIO_OFF, valp, NULL);
}

int cxl_get_base_image(char* devname, long *valp)
{
	return cxl_read_sysfs(devname, BASE_IMAGE, valp, NULL);
}

int cxl_get_caia_version(char* devname, long *majorp, long *minorp)
{
	return cxl_read_sysfs(devname, CAIA_VERSION, majorp, minorp);
}

int cxl_get_image_loaded(char* devname, enum cxl_image *valp)
{
	return cxl_read_sysfs(devname, IMAGE_LOADED, (long *)valp, NULL);
}

int cxl_get_psl_revision(char* devname, long *valp)
{
	return cxl_read_sysfs(devname, PSL_REVISION, valp, NULL);
}
