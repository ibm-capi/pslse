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

#include <errno.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "debug.h"
#include "utils.h"

#ifndef __APPLE__
// Is this a little endian machine?
static uint16_t _is_little_endian(void)
{
	union {
		uint16_t i16;
		uint8_t i8[sizeof(uint16_t)];
	}
	u;
	u.i16 = 1;
	return u.i8[0];
}

uint64_t htonll(uint64_t hostlonglong)
{
	if (_is_little_endian()) {
		return (((uint64_t) (htonl((uint32_t) hostlonglong))) << 32) |
		    ((uint64_t) (htonl((uint32_t) (hostlonglong >> 32))));
	}

	return hostlonglong;
}

uint64_t ntohll(uint64_t netlonglong)
{
	return htonll(netlonglong);
}
#endif				/* __APPLE__ */

// Display fatal message (For catching coding bugs, not AFU bugs)
void fatal_msg(const char *format, ...)
{
	va_list args;

	fflush(stdout);
	fprintf(stderr, "FATAL:");
	va_start(args, format);
	vfprintf(stderr, format, args);
	va_end(args);
	fprintf(stderr, "!\n");
	fflush(stderr);
}

// Display error message
void error_msg(const char *format, ...)
{
	va_list args;

	fflush(stdout);
	fprintf(stderr, "ERROR:");
	va_start(args, format);
	vfprintf(stderr, format, args);
	va_end(args);
	fprintf(stderr, "!\n");
	fflush(stderr);
	exit(-1);
}

// Display warning message
void warn_msg(const char *format, ...)
{
	va_list args;

	fflush(stdout);
	fprintf(stderr, "WARNING:");
	va_start(args, format);
	vfprintf(stderr, format, args);
	va_end(args);
	fprintf(stderr, "!\n");
	fflush(stderr);
}

// Display informational message
void info_msg(const char *format, ...)
{
	va_list args;

	fflush(stdout);
	printf("INFO:");
	va_start(args, format);
	vprintf(format, args);
	va_end(args);
	printf("\n");
	fflush(stdout);
}

// Display debug message
void debug_msg(const char *format, ...)
{
#ifdef DEBUG
	va_list args;

	fflush(stdout);
	printf("DEBUG:");
	va_start(args, format);
	vprintf(format, args);
	va_end(args);
	printf("\n");
#endif				/* DEBUG */
	fflush(stdout);
}

// Delay for up to ns nanoseconds
void ns_delay(long ns)
{
	struct timespec ts;
	ts.tv_sec = 0;
	ts.tv_nsec = ns;
	nanosleep(&ts, &ts);
}

// Delay to allow another thread to have mutex lock
void lock_delay(pthread_mutex_t * lock)
{
	pthread_mutex_unlock(lock);
	ns_delay(100000);
	pthread_mutex_lock(lock);
}

// Is there incoming data on socket?
int bytes_ready(int fd, int timeout, int *abort)
{
	struct pollfd pfd;
	int rc;

	pfd.fd = fd;
	pfd.events = POLLIN | POLLHUP;
	pfd.revents = 0;
	do {
		rc = poll(&pfd, 1, timeout);
	}
	while ((rc < 0) && (errno == EINTR));
	if ((abort != NULL) && (*abort != 0))
		return -1;
	if (rc == 0)
		return 0;
	if ((rc > 0) && !(pfd.revents & POLLHUP))
		return 1;
	warn_msg("Socket disconnect on poll");
	return -1;
}

// Get bytes from socket
int get_bytes_silent(int fd, int size, uint8_t * data, int timeout, int *abort)
{
	int count, bytes, rc;

	bytes = 0;
	while (bytes < size) {
		// Check for socket activity

		rc = bytes_ready(fd, timeout, abort);
		if (rc == 0) {
			warn_msg("Socket timeout");
			break;
		}
		if (rc < 0) {
			warn_msg("bytes_ready:Socket disconnect");
			break;
		}

		bytes = recv(fd, data, size - bytes, MSG_PEEK | MSG_DONTWAIT);
		if (((bytes < 0) && (errno != EINTR)) || !bytes) {
			warn_msg("get_bytes_silent:Socket disconnect on recv");
			return -1;
		}
	}

	if (bytes < size)
		return -1;

	bytes = 0;
	while (data && (bytes < size)) {
		count = recv(fd, &(data[bytes]), size, 0);
		if (count <= 0) {
			if (errno != EINTR)
				break;
			else
				continue;
		}
		bytes += count;
	}

#if DEBUG
	DPRINTF("DEBUG:SOCKET IN:0x");
	for (count = 0; count < bytes; count++)
		DPRINTF("%02x", data[count]);
	DPRINTF("\n");
#endif				/* DEBUG */

	return 0;
}

// Get bytes from socket with debug output
int get_bytes(int fd, int size, uint8_t * data, int timeout, int *abort,
	      FILE * dbg_fp, uint8_t dbg_id, uint16_t context)
{
	int rc;

	rc = get_bytes_silent(fd, size, data, timeout, abort);
	if (rc == 0)
		debug_socket_get(dbg_fp, dbg_id, context, data[0]);
	return rc;
}

// Put bytes on socket
int put_bytes_silent(int fd, int size, uint8_t * data)
{
	int count, bytes;

	bytes = 0;
	while (data && (bytes < size)) {
		count = write(fd, &(data[bytes]), size);
		if (count < 0) {
			if (errno == EINTR)
				continue;
			else
				return -1;
		}
		bytes += count;
	}

#if DEBUG
	DPRINTF("DEBUG:SOCKET OUT:0x");
	for (count = 0; count < bytes; count++)
		DPRINTF("%02x", data[count]);
	DPRINTF("\n");
#endif				/* DEBUG */

	return bytes;
}

// Put bytes on socket with debug output;
int put_bytes(int fd, int size, uint8_t * data, FILE * dbg_fp, uint8_t dbg_id,
	      uint16_t context)
{
	int bytes;

	bytes = put_bytes_silent(fd, size, data);
	if (bytes == size)
		debug_socket_put(dbg_fp, dbg_id, context, data[0]);

	return bytes;
}

// Generate parity for up to 64bits of data
uint8_t generate_parity(uint64_t data, uint8_t odd)
{
	uint8_t parity = odd;
	// While at least 1 bit is set
	while (data) {
		// Invert parity bit
		parity = 1 - parity;
		// Zero out least significant bit that is set to 1
		data &= data - 1;
	}
	return parity;
}

// Generate parity for entire cacheline of data
void generate_cl_parity(uint8_t * data, uint8_t * parity)
{
	int i;
	uint64_t dw;
	uint8_t p;

	// Walk each double word (dword) in cacheline
	for (i = 0; i < DWORDS_PER_CACHELINE; i++) {
		// Copy dword of data into uint64_t dw
		memcpy(&dw, &(data[BYTES_PER_DWORD * i]), BYTES_PER_DWORD);
		// Initialize parity entry to 0 when starting parity byte
		if ((i % BYTES_PER_DWORD) == 0)
			parity[i / BYTES_PER_DWORD] = 0;
		// Shift previously calculated parity bits left
		parity[i / BYTES_PER_DWORD] <<= 1;
		// Generate parity bit for this dword
		p = generate_parity(dw, ODD_PARITY);
		parity[i / BYTES_PER_DWORD] += p;
	}
}

// Gracefully shutdown and close socket connection
int close_socket(int *sockfd)
{
	char buffer[4096];
	int yes = 1;

	// Shutdown socket traffic
	if (shutdown(*sockfd, SHUT_RDWR))
		return -1;

	// Drain any data in socket
	while (recv(*sockfd, buffer, sizeof(buffer) - 1, MSG_DONTWAIT) > 0) ;

	// Close socket
	setsockopt(*sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));
	if (close(*sockfd))
		return -1;
	*sockfd = -1;

	return 0;
}

#if defined PSL9
// sign extend a 32bit integer
int32_t sign_extend (uint32_t in_op)
{
	int32_t lvalue;
	lvalue = (uint32_t) (1 << 31);
	if ((in_op & lvalue) != 0)
		in_op |= ~(lvalue-1);
	else
		in_op &= (lvalue-1);
	return in_op;
}
// sign extend a 64bit integer
int64_t sign_extend64 (uint64_t in_op)
{
	int64_t lvalue;
	//lvalue = (uint64_t) (1ULL << 63);
	lvalue = 1ULL << 63;
	if ((in_op & lvalue) != 0)
		in_op |= ~(lvalue-1);
	else
		in_op &= (lvalue-1);
	return in_op;
}

#endif
