/*
 * Copyright 2014,2016 International Business Machines
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

#ifndef _UTILS_H_
#define _UTILS_H_

#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include "psl_interface_t.h"

#ifdef DEBUG
#define DPRINTF(...) printf(__VA_ARGS__)
#else
#define DPRINTF(...)
#endif

#define MAX_LINE_CHARS 1024

#define ODD_PARITY 1
#define BYTES_PER_DWORD 8
#define DWORDS_PER_CACHELINE 16
#define CACHELINE_BYTES 128
#define PSL_IDLE_CYCLES 20

#ifdef PSL8
#define PSLSE_VERSION_MAJOR	0x01
#define PSLSE_VERSION_MINOR	0x02
#endif /* ifdef PSL8 */

#if defined PSL9lite || defined PSL9
#define PSLSE_VERSION_MAJOR	0x02
#define PSLSE_VERSION_MINOR	0x00
#endif /* ifdef PSL9 */

#define PSLSE_CONNECT		0x01
#define PSLSE_QUERY		0x02
#define PSLSE_MAX_INT		0x03
#define PSLSE_OPEN		0x04
#define PSLSE_ATTACH		0x05
#define PSLSE_DETACH		0x06
#define PSLSE_MEMORY_READ	0x07
#define PSLSE_MEMORY_WRITE	0x08
#define PSLSE_MEMORY_TOUCH	0x09
#define PSLSE_MEM_SUCCESS	0x0a
#define PSLSE_MEM_FAILURE	0x0b
#define PSLSE_MMIO_MAP		0x0c
#define PSLSE_MMIO_READ64	0x0d
#define PSLSE_MMIO_WRITE64	0x0e
#define PSLSE_MMIO_READ32	0x0f
#define PSLSE_MMIO_WRITE32	0x10
#define PSLSE_MMIO_ACK		0x11
#define PSLSE_MMIO_FAIL		0x12
#define PSLSE_INTERRUPT		0x13
#define PSLSE_AFU_ERROR		0x14
#define PSLSE_MMIO_EBREAD	0x15
#define PSLSE_VSEC_INFO		0x16

// PSLSE states
enum pslse_state {
	PSLSE_IDLE,
	PSLSE_RESET,
	PSLSE_DESC,
	PSLSE_PENDING,
	PSLSE_RUNNING,
	PSLSE_DONE
};

#ifndef __APPLE__
// Convert host to network byte ordering
uint64_t htonll(uint64_t hostlonglong);

// Convert network to host byte ordering
uint64_t ntohll(uint64_t netlonglong);
#endif				/* __APPLE__ */

// Display fatal message (For catching code bugs, not AFU bugs)
void fatal_msg(const char *format, ...);

// Display error message
void error_msg(const char *format, ...);

// Display warning message
void warn_msg(const char *format, ...);

// Display informational message
void info_msg(const char *format, ...);

// Display debug message
void debug_msg(const char *format, ...);

// Delay for up to ns nanoseconds
void ns_delay(long ns);

// Delay to allow another thread to have mutex lock
void lock_delay(pthread_mutex_t * lock);

// Is there incoming data on socket?
int bytes_ready(int fd, int timeout, int *abort);

// Allocate memory for data and get size bytes from fd, no debug
int get_bytes_silent(int fd, int size, uint8_t * data, int timeout, int *abort);

// Allocate memory for data and get size bytes from fd
int get_bytes(int fd, int size, uint8_t * data, int timeout, int *abort,
	      FILE * dbg_fp, uint8_t dbg_id, uint16_t context);

// Put bytes on socket and return number of bytes successfully written, no debug
int put_bytes_silent(int fd, int size, uint8_t * data);

// Put bytes on socket and return number of bytes successfully written
int put_bytes(int fd, int size, uint8_t * data, FILE * dbg_fp, uint8_t dbg_id,
	      uint16_t context);

// Generate parity for outbound data and checking inbound data
// 1 bit of parity for up to 64 bits of data
uint8_t generate_parity(uint64_t data, uint8_t odd);

// Generate parity for entire cacheline
// 1 bit of parity for each 64 bits of data
void generate_cl_parity(uint8_t * data, uint8_t * parity);

// Gracefully shutdown and close socket connection
int close_socket(int *sockfd);

#endif				/* _UTILS_H_ */
