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

/*
 * Description: pslse.c
 *
 *  This file contains the main loop for the PSLSE proxy that connects to AFU
 *  simulator(s) and allows client applications to connect for accessing the
 *  AFU(s).  When PSLSE is executed parse_host_data() is called to find and
 *  connect to any AFU simulators specified in the shim_host.dat file. Each
 *  successful simulator connection will cause a seperate thread to be launched.
 *  The code for those threads is in psl.c.  As long as at least one simulator
 *  connection is valid then PSLSE will remain active and awaiting client
 *  connections.  Each time a valid client connection is made it will be
 *  assigned to the appropriate psl thread for whichever AFU it is accessing.
 *  If it is the first client to connect then the AFU is reset and the AFU
 *  descriptor is read.
 */

#include <assert.h>
#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <malloc.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <termios.h>
#include <time.h>

#include "mmio.h"
#include "parms.h"
#include "psl.h"
#include "shim_host.h"
#include "../common/debug.h"
#include "../common/utils.h"

#define PSLSE_VERSION 1

struct psl* psl_list;
FILE *fp;

static int get_key()
{
	int character;
	struct termios orig, temp;

	// Display echo and set to non-canonial mode for stdin
	tcgetattr(fileno(stdin), &orig);
	memcpy(&temp, &orig, sizeof(struct termios));
	temp.c_lflag &= ~(ECHO|ICANON);
	tcsetattr(fileno(stdin), TCSANOW, &temp);

	// Get key pressed
	character = fgetc(stdin);

	// Restore stdin settings
	tcsetattr(fileno(stdin), TCSANOW, &orig);

	// Only accept 1-4 as valid inputs
	character -= (int) '0';
	if (character < 1)
		character = 0;
	if (character > 4)
		character = 0;

	return character;
}

static void disconnect_afu()
{
	// Shut down PSL threads
	struct psl* psl;
	int i, key;

	psl = psl_list;
	if (psl == NULL)
		return;

	printf("\n\n");
	printf("Choose an AFU to disconnect or any other key to continue:\n");
	printf("\n");
	i = 1;
	while (psl) {
		printf("\t%d) %s\n", i, psl->name);
		psl = psl->_next;
		++i;
	}
	printf("\n");

	key = get_key();
	if ((key == 0) || (key >= i)) {
		warn_msg("Invalid selection, resuming");
		return;
	}

	i = 1;
	psl = psl_list;
	while (i < key) {
		psl = psl->_next;
		++i;
	}
	info_msg("Shutting down connection to %s\n", psl->name);
	psl_list->state = PSLSE_DONE;
	pthread_join(psl->thread, NULL);
	disconnect_afu();
}

// Disconnect client connections and stop threads gracefully on Ctrl-C
static void _INThandler(int sig)
{
	disconnect_afu();
}

// Handshake with client and attach to PSL
static int _client_connect(int fd, char *ip, int timeout)
{
	struct psl* psl;
	struct client *client;
	uint8_t *buffer;
	uint8_t rc[2];
	char afu_type;
	uint8_t n;
	uint32_t mmio_offset, mmio_size;
	int i;

	// Parse client handshake data
	rc[0] = PSLSE_DETACH;
	buffer = get_bytes(fd, 5, timeout, fp, -1, -1);
	if ((buffer == NULL) || (strcmp((char *) buffer, "PSLSE"))) {
		info_msg("Connecting application is not PSLSE client\n");
		info_msg("Expected: \"PSLSE\" Got: \"%s\"", buffer);
		put_bytes(fd, 1, &(rc[0]), 10000, fp, -1, -1);
		close (fd);
		return -1;
	}
	free(buffer);
	buffer = get_bytes_silent(fd, 1, timeout);
	if ((buffer == NULL) || ((uint8_t) buffer[0] != PSLSE_VERSION)) {
		info_msg("Client is wrong version\n");
		put_bytes(fd, 1, &(rc[0]), timeout, fp, -1, -1);
		close (fd);
		return -1;
	}
	free(buffer);
	buffer = get_bytes_silent(fd, 1, timeout);
	if (buffer == NULL) {
		info_msg("Client didn't specify length of AFU name\n");
		put_bytes(fd, 1, &(rc[0]), timeout, fp, -1, -1);
		close (fd);
		return -1;
	}
	n = (uint8_t) buffer[0];
	free(buffer);
	buffer = get_bytes_silent(fd, n, timeout);
	if (buffer == NULL) {
		info_msg("Client didn't specify AFU name\n");
		put_bytes(fd, 1, &(rc[0]), timeout, fp, -1, -1);
		close (fd);
		return -1;
	}
	afu_type = (char) buffer[strlen((char *) buffer)-1];
	buffer[strlen((char *) buffer)-1] = '\0';

	// Associate with PSL
	psl = psl_list;
	while (psl) {
		if (!strcmp((char *) buffer, psl->name))
			break;
		psl = psl->_next;
	}
	if (!psl) {
		info_msg("Did not find valid PSL for AFU %s\n", buffer);
		free(buffer);
		put_bytes(fd, 1, &(rc[0]), timeout, fp, -1, -1);
		close (fd);
		return -1;
	}

	// See if this is first client connecting to PSL
	mmio_size = 0;
	if (!psl->client) {
		mmio_size = MMIO_FULL_RANGE;
		add_job(psl->job, PSL_JOB_RESET, 0L);
		psl->state = PSLSE_RESET;
		while (psl->state != PSLSE_IDLE) ns_delay(4);
		psl->state = PSLSE_DESC;
		read_descriptor(psl->mmio);
		psl->state = PSLSE_IDLE;
		if ((psl->mmio->desc.req_prog_model & 0x7fffl) ==
		    PROG_MODEL_DEDICATED) {
			// Dedicated AFU
			psl->max_clients = 1;
		}
		if ((psl->mmio->desc.req_prog_model & 0x7fffl) ==
		    PROG_MODEL_DIRECTED) {
			// Dedicated AFU
			psl->max_clients = psl->mmio->desc.num_of_processes;
		}
		if (psl->max_clients == 0) {
			error_msg("AFU programming model is invalid");
			free(buffer);
			put_bytes(fd, 1, &(rc[0]), timeout, fp, psl->dbg_id,
				  -1);
			close (fd);
			return -1;
		}
		psl->client = (struct client *)
			      malloc(sizeof(struct client)*psl->max_clients);
		psl->cmd->client = psl->client;
		memset((void *) psl->client, 0,
		       sizeof(struct client)*psl->max_clients);
	}

	// Check AFU type is valid for connection
	switch(afu_type) {
	case 'd':
		if (!(psl->mmio->desc.req_prog_model & PROG_MODEL_DEDICATED)) {
			warn_msg("AFU %s is does not support dedicated mode\n",
				 buffer);
			free(buffer);
			put_bytes(fd, 1, &(rc[0]), timeout, fp, psl->dbg_id,
				  -1);
			close (fd);
			return -1;
		}
		break;
	case 'm':
	case 's':
		if (!(psl->mmio->desc.req_prog_model & PROG_MODEL_DIRECTED)) {
			warn_msg("AFU %s is does not support directed mode\n",
				 buffer);
			free(buffer);
			put_bytes(fd, 1, &(rc[0]), timeout, fp, psl->dbg_id,
				 -1);
			close (fd);
			return -1;
		}
		break;
	default:
		warn_msg("AFU device type '%c' is not valid\n", afu_type);
		free(buffer);
		put_bytes(fd, 1, &(rc[0]), timeout, fp, psl->dbg_id, -1);
		return -1;
	}

	// Look for open client slot
	assert (psl->max_clients > 0);
	for(i = 0; i < psl->max_clients; i++) {
		if ((psl->client[i].valid == 0) &&
		    (psl->client[i].mem_access == NULL)) {
			client = &(psl->client[i]);
			client->context = i;
			break;
		}
	}
	if (i == psl->max_clients) {
		info_msg("No room for new client on AFU %s\n", buffer);
		free(buffer);
		put_bytes(fd, 1, &(rc[0]), timeout, fp, psl->dbg_id, -1);
		close (fd);
		return -1;
	}

	// Attach to PSL
	rc[0] = PSLSE_ATTACH;
	rc[1] = client->context;
	mmio_offset = 0;
	if (mmio_size==0) {
		if (psl->mmio->desc.PerProcessPSA & PROCESS_PSA_REQUIRED) {
			mmio_size = psl->mmio->desc.PerProcessPSA & PSA_MASK;
			mmio_size *= FOUR_K;
			mmio_offset = psl->mmio->desc.PerProcessPSA_offset;
			mmio_offset += mmio_size * i;
		}
		else {
			mmio_size = MMIO_FULL_RANGE;
		}
	}
	memset((void *) &(psl->client[i]), 0, sizeof(struct client));
	client->mmio_size = mmio_size;
	client->mmio_offset = mmio_offset;
	client->type = afu_type;
	put_bytes(fd, 2, &(rc[0]), timeout, fp, psl->dbg_id, client->context);
	free(buffer);
	client->fd = fd;
	client->ip = ip;
	client->valid = 1;
	info_msg("%s connected to %s with context %d", client->ip,
		psl->name, i);

	// DEBUG
	debug_context_add(fp, psl->dbg_id, client->context);

	return 0;
}

static int _start_server()
{
	struct sockaddr_in serv_addr;
	int listen_fd, port, bound;
	char hostname[MAX_LINE_CHARS];

	// Start server
	port = 16384;
	bound = 0;
	listen_fd = -1;
	memset(&serv_addr, 0, sizeof(serv_addr));
	listen_fd = socket(AF_INET, SOCK_STREAM, 0);
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	while (!bound) {
		serv_addr.sin_port = htons(port);
		if (bind(listen_fd, (struct sockaddr *)&serv_addr,
			 sizeof(serv_addr)) < 0) {
			if (errno!=EADDRINUSE) {
				perror("bind");
				return -1;
			}
			if (port == 0xFFFF) {
				perror("bind");
				return -1;
			}
			++port;
			continue;
		}
		bound = 1;
	}
	listen(listen_fd, 4); // FIXME: constant 4
	hostname[MAX_LINE_CHARS-1] = '\0';
	gethostname(hostname, 1023);
	info_msg("Started PSLSE server, listening on %s:%d", hostname, port);

	return listen_fd;
}

//
// Main
//

int main(int argc, char **argv)
{
	struct sockaddr_in client_addr;
	int listen_fd, connect_fd;
	socklen_t client_len;
	sigset_t set;
	struct sigaction action;
	struct parms *parms;
	char *ip;

	// Open debug.log file
	fp = fopen("debug.log", "w");

	// Mask SIGPIPE signal for all threads
	sigemptyset(&set);
	sigaddset(&set, SIGPIPE);
	if (pthread_sigmask(SIG_BLOCK, &set, NULL)) {
		perror("pthread_sigmask");
		return -1;
	}

	// Catch SIGINT for graceful termination
	action.sa_handler = _INThandler;
	sigemptyset(&(action.sa_mask));
	action.sa_flags = 0;
	sigaction(SIGINT, &action, NULL);

	// Parse parameters file
	parms = parse_parms("pslse.parms", fp);
	if (parms == NULL) {
		error_msg("Unable to parse pslse.parms file");
		return -1;
	}

	// Connect to simulator(s) and start psl thread(s)
	parse_host_data(&psl_list, parms, "shim_host.dat", fp);
	if (psl_list == NULL) {
		free(parms);
		fclose(fp);
		error_msg("Unable to connect to any simulators");
		return -1;
	}

	// Start server
	if ((listen_fd = _start_server()) < 0) {
		free(parms);
		fclose(fp);
		return -1;
	}

	// Watch for client connections
	while (psl_list != NULL) {
		// Wait for next client to connect
		client_len = sizeof(client_addr);
		connect_fd = accept(listen_fd, (struct sockaddr *)&client_addr,
				    &client_len);
		if (connect_fd < 0)
			continue;
		ip = (char *)malloc(INET_ADDRSTRLEN+1);
		inet_ntop(AF_INET, &(client_addr.sin_addr.s_addr), ip,
			  INET_ADDRSTRLEN);
		info_msg("Connection from %s", ip);
		_client_connect(connect_fd, ip, parms->timeout);
	}
	info_msg("No AFUs connected, Shutting down PSLSE\n");

	free(parms);
	fclose(fp);

	return 0;
}
