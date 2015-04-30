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

#include <malloc.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "utils.h"

// Usage message
void usage(int argc, char **argv)
{
	fflush(stderr);
	printf("\nUsage: %s HOST:PORT\n\n", argv[0]);
	exit(1);
}

// Display fatal message (For catching coding bugs, not AFU bugs)
void fatal_msg(char *format, ...)
{
	va_list args;

	fflush(stdout);
	fprintf(stderr, "FATAL : ");
	va_start(args, format);
	vfprintf(stderr, format, args);
	va_end(args);
	fprintf(stderr, "!\n");
	fflush(stderr);
}

// Display error message
void error_msg(char *format, ...)
{
	va_list args;

	fflush(stdout);
	fprintf(stderr, "ERROR : ");
	va_start(args, format);
	vfprintf(stderr, format, args);
	va_end(args);
	fprintf(stderr, "!\n");
	fflush(stderr);
	exit(-1);
}

// Display error message
void warn_msg(char *format, ...)
{
	va_list args;

	fflush(stdout);
	fprintf(stderr, "WARNING : ");
	va_start(args, format);
	vfprintf(stderr, format, args);
	va_end(args);
	fprintf(stderr, "!\n");
	fflush(stderr);
}

// Display error message
void info_msg(char *format, ...)
{
	va_list args;

	fflush(stdout);
	printf("INFO : ");
	va_start(args, format);
	vprintf(format, args);
	va_end(args);
	printf("\n");
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

// Get bytes from socket
uint8_t * get_bytes(int fd, unsigned size, int timeout)
{
	struct pollfd pfd;
	uint8_t *data;
	int count, bytes;

	data = (uint8_t *) malloc(size+1);
	memset(data, 0, size+1);

	bytes = 0;
	pfd.fd = fd;
	pfd.events = POLLIN | POLLHUP;
	pfd.revents = 0;
	while (data && (bytes < size)) {
		if (poll(&pfd, 1, timeout) <= 0) {
			break;
		}
		if ((bytes = recv(fd, data, size, MSG_PEEK|MSG_DONTWAIT))==0) {
			free(data);
			data = NULL;
DPRINTF("Socket disconnect\n");
			break;
		}
	}

	if (bytes == size) {
		bytes = 0;
		while (data && (bytes < size)) {
			count = recv(fd, &(data[bytes]), size, 0);
			if (count <= 0)
				break;
			bytes += count;
		}
#if DEBUG
		DPRINTF("Socket in:0x");
		for (count = 0; count < bytes; count++)
			DPRINTF("%02x", data[count]);
		DPRINTF("\n");
#endif /* DEBUG */
	}

	return data;
}

// Put bytes on socket
int put_bytes(int fd, unsigned size, uint8_t *data, int timeout)
{
	struct timespec start, now;
	int count, bytes;
	double milliseconds;

	if (clock_gettime(CLOCK_REALTIME, &start) < 0) {
		perror("clock_gettime");
		return 0;
	}
#if DEBUG
	int i;
	DPRINTF("Socket out:0x");
#endif /* DEBUG */
	now = start;
	bytes = 0;
	while (data && (bytes < size)) {
		count = write(fd, &(data[bytes]), size);
		if (count < 0)
			break;
#if DEBUG
		for (i = bytes; i < count + bytes; i++)
			DPRINTF("%02x", data[i]);
#endif /* DEBUG */
		bytes += count;
		if (clock_gettime(CLOCK_REALTIME, &now) < 0) {
			perror("clock_gettime");
			break;
		}
		milliseconds = (double) (now.tv_sec - start.tv_sec) *
			       (double) 1000L +
			       (double) (now.tv_nsec - start.tv_nsec) /
			       (double) (1000000L);
		if ((timeout > 0) && (((int) milliseconds) > timeout)) {
			DPRINTF("Timeout waiting to put data on socket!\n");
			break;
		}
	}
	DPRINTF("\n");

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
