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

#include "client.h"
#include "mmio.h"
#include "parms.h"
#include "psl.h"
#include "shim_host.h"
#include "../common/debug.h"
#include "../common/utils.h"

#define PSLSE_VERSION 1
#define PSL_MAX_IRQS 2037

struct psl* psl_list;
struct client* client_list;
pthread_mutex_t client_lock;
uint16_t afu_map;
int timeout;
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
		return;
	}

	i = 1;
	psl = psl_list;
	while (i < key) {
		psl = psl->_next;
		++i;
	}
	info_msg("Shutting down connection to %s\n", psl->name);
	psl->state = PSLSE_DONE;
	pthread_join(psl->thread, NULL);
	disconnect_afu();
}

// Disconnect client connections and stop threads gracefully on Ctrl-C
static void _INThandler(int sig)
{
	// Flush debug output
	fflush(fp);
	// Handle AFU disconnect
	disconnect_afu();
}

// Handshake with client and attach to PSL
static struct client *_client_connect(int fd, char *ip)
{
	struct client *client;
	uint8_t *buffer;
	uint8_t rc[3];
	uint16_t map;

	// Parse client handshake data
	rc[0] = PSLSE_DETACH;
	buffer = get_bytes(fd, 5, timeout, fp, -1, -1);
	if ((buffer == NULL) || (strcmp((char *) buffer, "PSLSE"))) {
		info_msg("Connecting application is not PSLSE client\n");
		info_msg("Expected: \"PSLSE\" Got: \"%s\"", buffer);
		put_bytes(fd, 1, &(rc[0]), 10000, fp, -1, -1);
		close (fd);
		return NULL;
	}
	free(buffer);
	buffer = get_bytes_silent(fd, 1, timeout);
	if ((buffer == NULL) || ((uint8_t) buffer[0] != PSLSE_VERSION)) {
		info_msg("Client is wrong version\n");
		put_bytes(fd, 1, &(rc[0]), timeout, fp, -1, -1);
		close (fd);
		return NULL;
	}
	free(buffer);

	// Initialize client struct
	client = (struct client *) calloc(1, sizeof(struct client));
	client->fd = fd;
	client->ip = ip;
	client->pending = 1;

	// Return acknowledge to client
	rc[0] = PSLSE_CONNECT;
	map = htole16(afu_map);
	memcpy(&(rc[1]), &map, sizeof(map));
	put_bytes(fd, 3, &(rc[0]), timeout, fp, -1, -1);

	info_msg("%s connected", client->ip);
	return client;
}

// Associate client to PSL
static int _client_associate(struct client *client, uint8_t id, char afu_type)
{
	struct psl* psl;
	uint8_t major, minor;
	uint32_t mmio_offset, mmio_size;
	int i;
	uint8_t rc[2];

	// Associate with PSL
	rc[0] = PSLSE_DETACH;
	major = id >> 4;
	minor = id & 0x3;
	psl = psl_list;
	while (psl) {
		if (id == psl->dbg_id)
			break;
		psl = psl->_next;
	}
	if (!psl) {
		info_msg("Did not find valid PSL for afu%d.%d\n", major, minor);
		put_bytes(client->fd, 1, &(rc[0]), timeout, fp, -1, -1);
		close (client->fd);
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
			put_bytes(client->fd, 1, &(rc[0]), timeout, fp,
				  psl->dbg_id, -1);
			close (client->fd);
			return -1;
		}
		psl->client = (struct client**)calloc(psl->max_clients,
						      sizeof(struct client*));
		psl->cmd->client = psl->client;
	}

	// Check AFU type is valid for connection
	switch(afu_type) {
	case 'd':
		if (!(psl->mmio->desc.req_prog_model & PROG_MODEL_DEDICATED)) {
			warn_msg("afu%d.%d is does not support dedicated mode\n"
				 ,major ,minor);
			put_bytes(client->fd, 1, &(rc[0]), timeout, fp,
				  psl->dbg_id, -1);
			close (client->fd);
			return -1;
		}
		break;
	case 'm':
	case 's':
		if (!(psl->mmio->desc.req_prog_model & PROG_MODEL_DIRECTED)) {
			warn_msg("afu%d.%d is does not support directed mode\n",
				 major, minor);
			put_bytes(client->fd, 1, &(rc[0]), timeout, fp,
				  psl->dbg_id, -1);
			close (client->fd);
			return -1;
		}
		break;
	default:
		warn_msg("AFU device type '%c' is not valid\n", afu_type);
		put_bytes(client->fd, 1, &(rc[0]), timeout, fp, psl->dbg_id,
			  -1);
		return -1;
	}

	// Look for open client slot
	assert (psl->max_clients > 0);
	pthread_mutex_lock(&client_lock);
	for(i = 0; i < psl->max_clients; i++) {
		if (psl->client[i]== NULL) {
			client->context = i;
			client->valid = 1;
			client->pending = 0;
			psl->client[i] = client;
			break;
		}
	}
	pthread_mutex_unlock(&client_lock);
	if (i == psl->max_clients) {
		info_msg("No room for new client on afu%d.%d\n", major, minor);
		put_bytes(client->fd, 1, &(rc[0]), timeout, fp, psl->dbg_id,
			  -1);
		close (client->fd);
		return -1;
	}

	// Attach to PSL
	rc[0] = PSLSE_OPEN;
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
	client->mmio_size = mmio_size;
	client->mmio_offset = mmio_offset;
	client->max_irqs = PSL_MAX_IRQS/psl->mmio->desc.num_of_processes;
	client->type = afu_type;
	put_bytes(client->fd, 2, &(rc[0]), timeout, fp, psl->dbg_id,
		  client->context);

	// DEBUG
	debug_context_add(fp, psl->dbg_id, client->context);

	return 0;
}

static void * _client_loop(void *ptr)
{
	struct client *client = (struct client*)ptr;
	uint8_t *data;

	while (client->pending) {
		data = get_bytes(client->fd, 1, 10, fp, -1, -1);
		if (data == NULL) {
			client->pending = 0;
			break;
		}
		if (data[0] == '\0') {
			free(data);
			continue;
		}
		if (data[0] != PSLSE_OPEN) {
			free(data);
			break;
		}
		free(data);
		data = get_bytes(client->fd, 2, timeout, fp, -1, -1);
		if (data == NULL) {
			client->pending = 0;
			break;
		}
		_client_associate(client, data[0], (char) data[1]);
		free(data);
		break;
	}

	// Terminate thread
	pthread_exit(NULL);
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
	struct client *client;
	struct client **client_ptr;
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
	timeout = parms->timeout;

	// Connect to simulator(s) and start psl thread(s)
	afu_map = parse_host_data(&psl_list, parms, "shim_host.dat", fp);
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
	pthread_mutex_init(&client_lock, NULL);
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
		// Clean up disconnected clients
		client_ptr = &client_list;
		while (*client_ptr != NULL) {
			client = *client_ptr;
			if ((client->pending == 0) && (client->valid== 0)) {
				printf("Removing detached client\n");
				*client_ptr = client->_next;
				if (client->_next != NULL)
					client->_next->_prev = client->_prev;
				free(client);
				continue;
			}
			client_ptr = &((*client_ptr)->_next);
		}
		// Add new client
		info_msg("Connection from %s", ip);
		client = _client_connect(connect_fd, ip);
		pthread_mutex_lock(&client_lock);
		if (client != NULL) {
			printf("Adding client\n");
			if (client_list != NULL)
				client_list->_prev = client;
			client->_next = client_list;
			if (pthread_create(&(client->thread), NULL,
					   _client_loop, client)) {
				perror("pthread_create");
				free(parms);
				fclose(fp);
				return -1;
			}
			client_list = client;
		}

		pthread_mutex_unlock(&client_lock);
	}
	info_msg("No AFUs connected, Shutting down PSLSE\n");

	// Shutdown unassociated client connections
	pthread_mutex_lock(&client_lock);
	while (client_list != NULL) {
		client = client_list;
		client_list = client->_next;
		if (client->pending)
			client->pending = 0;
		pthread_mutex_unlock(&client_lock);
		pthread_join(client->thread, NULL);
		free(client);
		pthread_mutex_lock(&client_lock);
	}
	pthread_mutex_unlock(&client_lock);

	free(parms);
	fclose(fp);

	return 0;
}
