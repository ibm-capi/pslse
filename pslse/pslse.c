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

#define PSL_MAX_IRQS 2037

struct psl *psl_list;
struct client *client_list;
pthread_mutex_t lock;
uint16_t afu_map;
int timeout;
FILE *fp;

// Disconnect client connections and stop threads gracefully on Ctrl-C
static void _INThandler(int sig)
{
	pthread_t thread;
	struct psl *psl;
	int i;

	// Flush debug output
	fflush(fp);

	// Shut down PSL threads
	psl = psl_list;
	while (psl != NULL) {
		info_msg("Shutting down connection to %s\n", psl->name);
		for (i = 0; i < psl->max_clients; i++) {
			if (psl->client[i] != NULL)
				psl->client[i]->abort = 1;
		}
		psl->state = PSLSE_DONE;
		thread = psl->thread;
		psl = psl->_next;
		pthread_join(thread, NULL);
	}
}

// Find PSL for specific AFU id
static struct psl *_find_psl(uint8_t id, uint8_t * major, uint8_t * minor)
{
	struct psl *psl;

	*major = id >> 4;
	*minor = id & 0x3;
	psl = psl_list;
	while (psl) {
		if (id == psl->dbg_id)
			break;
		psl = psl->_next;
	}
	return psl;
}

// Query AFU descriptor data
static void _query(struct client *client, uint8_t id)
{
	struct psl *psl;
	uint8_t *buffer;
	uint8_t major, minor;
	int size, offset;

	psl = _find_psl(id, &major, &minor);
	size = 1 + sizeof(psl->mmio->desc.num_ints_per_process) + sizeof(client->max_irqs) + 
	    sizeof(psl->mmio->desc.req_prog_model) +
	    sizeof(psl->mmio->desc.PerProcessPSA) + sizeof(psl->mmio->desc.PerProcessPSA_offset) +
	    sizeof(psl->mmio->desc.AFU_EB_len) + sizeof(psl->mmio->desc.crptr->cr_device) +
	    sizeof(psl->mmio->desc.crptr->cr_vendor) + sizeof(psl->mmio->desc.crptr->cr_class);
	buffer = (uint8_t *) malloc(size);
	buffer[0] = PSLSE_QUERY;
	offset = 1;
	memcpy(&(buffer[offset]),
	       (char *)&(psl->mmio->desc.num_ints_per_process),
	       sizeof(psl->mmio->desc.num_ints_per_process));
	offset += sizeof(psl->mmio->desc.num_ints_per_process);
	if (client->max_irqs == 0)
		client->max_irqs = 2037 / psl->mmio->desc.num_of_processes;
	memcpy(&(buffer[offset]),
	       (char *)&(client->max_irqs), sizeof(client->max_irqs));
        offset += sizeof(client->max_irqs);
	memcpy(&(buffer[offset]),
	       (char *)&(psl->mmio->desc.req_prog_model),
	       sizeof(psl->mmio->desc.req_prog_model));
        offset += sizeof(psl->mmio->desc.req_prog_model);
	memcpy(&(buffer[offset]),
	       (char *)&(psl->mmio->desc.PerProcessPSA),
	       sizeof(psl->mmio->desc.PerProcessPSA));
        offset += sizeof(psl->mmio->desc.PerProcessPSA);
	memcpy(&(buffer[offset]),
	       (char *)&(psl->mmio->desc.PerProcessPSA_offset),
	       sizeof(psl->mmio->desc.PerProcessPSA_offset));
        offset += sizeof(psl->mmio->desc.PerProcessPSA_offset);
	memcpy(&(buffer[offset]),
	       (char *)&(psl->mmio->desc.AFU_EB_len),
	       sizeof(psl->mmio->desc.AFU_EB_len));
        offset += sizeof(psl->mmio->desc.AFU_EB_len);
	memcpy(&(buffer[offset]),
	       (char *)&(psl->mmio->desc.crptr->cr_device),
	       sizeof(psl->mmio->desc.crptr->cr_device));
        offset += sizeof(psl->mmio->desc.crptr->cr_device);
	memcpy(&(buffer[offset]),
	       (char *)&(psl->mmio->desc.crptr->cr_vendor),
	       sizeof(psl->mmio->desc.crptr->cr_vendor));
        offset += sizeof(psl->mmio->desc.crptr->cr_vendor);
	memcpy(&(buffer[offset]),
	       (char *)&(psl->mmio->desc.crptr->cr_class),
	       sizeof(psl->mmio->desc.crptr->cr_class));
	if (put_bytes(client->fd, size, buffer, psl->dbg_fp, psl->dbg_id,
		      client->context) < 0) {
		client_drop(client, PSL_IDLE_CYCLES, CLIENT_NONE);
	}
	free(buffer);
}

// Increase the maximum number of interrupts
static void _max_irqs(struct client *client, uint8_t id)
{
	struct psl *psl;
	uint8_t buffer[MAX_LINE_CHARS];
	uint8_t major, minor;
	uint16_t value;

	// Retrieve requested new maximum interrupts
	psl = _find_psl(id, &major, &minor);
	if (get_bytes(client->fd, 2, buffer, psl->timeout, &(client->abort),
		      psl->dbg_fp, psl->dbg_id, client->context) < 0) {
		client_drop(client, PSL_IDLE_CYCLES, CLIENT_NONE);
		return;
	}
	memcpy((char *)&client->max_irqs, (char *)buffer, sizeof(uint16_t));
	client->max_irqs = ntohs(client->max_irqs);

	// Limit to legal value
	if (client->max_irqs < psl->mmio->desc.num_ints_per_process)
		client->max_irqs = psl->mmio->desc.num_ints_per_process;
	if (client->max_irqs > 2037 / psl->mmio->desc.num_of_processes)
		client->max_irqs = 2037 / psl->mmio->desc.num_of_processes;

	// Return set value
	buffer[0] = PSLSE_MAX_INT;
	value = htons(client->max_irqs);
	memcpy(&(buffer[1]), (char *)&value, 2);
	if (put_bytes(client->fd, 3, buffer, psl->dbg_fp, psl->dbg_id,
		      client->context) < 0) {
		client_drop(client, PSL_IDLE_CYCLES, CLIENT_NONE);
	}
}

static void _free_client(struct client *client)
{
	if (client == NULL)
		return;

	if (client->ip)
		free(client->ip);

	free(client);
}

// Handshake with client and attach to PSL
static struct client *_client_connect(int *fd, char *ip)
{
	struct client *client;
	uint8_t buffer[MAX_LINE_CHARS];
	uint8_t ack[3];
	uint16_t map;
	int rc;

	// Parse client handshake data
	ack[0] = PSLSE_DETACH;
	memset(buffer, '\0', MAX_LINE_CHARS);
	rc = get_bytes(*fd, 5, buffer, timeout, 0, fp, -1, -1);
	if ((rc < 0) || (strcmp((char *)buffer, "PSLSE"))) {
		info_msg("Connecting application is not PSLSE client\n");
		info_msg("Expected: \"PSLSE\" Got: \"%s\"", buffer);
		put_bytes(*fd, 1, ack, fp, -1, -1);
		close_socket(fd);
		return NULL;
	}
	rc = get_bytes_silent(*fd, 2, buffer, timeout, 0);
	if ((rc < 0) || ((uint8_t) buffer[0] != PSLSE_VERSION_MAJOR) ||
	    ((uint8_t) buffer[1] != PSLSE_VERSION_MINOR)) {
		info_msg("Client is wrong version\n");
		put_bytes(*fd, 1, ack, fp, -1, -1);
		close_socket(fd);
		return NULL;
	}
	// Initialize client struct
	client = (struct client *)calloc(1, sizeof(struct client));
	client->fd = *fd;
	client->ip = ip;
	client->pending = 1;
	client->timeout = timeout;
	client->flushing = FLUSH_NONE;
	client->state = CLIENT_INIT;

	// Return acknowledge to client
	ack[0] = PSLSE_CONNECT;
	map = htons(afu_map);
	memcpy(&(ack[1]), &map, sizeof(map));
	if (put_bytes(client->fd, 3, ack, fp, -1, -1) < 0) {
		_free_client(client);
		return NULL;
	}

	info_msg("%s connected", client->ip);
	return client;
}

// Associate client to PSL
static int _client_associate(struct client *client, uint8_t id, char afu_type)
{
	struct psl *psl;
	uint32_t mmio_offset, mmio_size;
	uint8_t major, minor;
	int i, context, clients;
	uint8_t rc[2];

	// Associate with PSL
	rc[0] = PSLSE_DETACH;
	psl = _find_psl(id, &major, &minor);
	if (!psl) {
		info_msg("Did not find valid PSL for afu%d.%d\n", major, minor);
		put_bytes(client->fd, 1, &(rc[0]), fp, -1, -1);
		close_socket(&(client->fd));
		return -1;
	}

	// Check AFU type is valid for connection
	switch (afu_type) {
	case 'd':
		if (!dedicated_mode_support(psl->mmio)) {
			warn_msg
			    ("afu%d.%d is does not support dedicated mode\n",
			     major, minor);
			put_bytes(client->fd, 1, &(rc[0]), fp, psl->dbg_id, -1);
			close_socket(&(client->fd));
			return -1;
		}
		break;
	case 'm':
	case 's':
		if (!directed_mode_support(psl->mmio)) {
			warn_msg("afu%d.%d is does not support directed mode\n",
				 major, minor);
			put_bytes(client->fd, 1, &(rc[0]), fp, psl->dbg_id, -1);
			close_socket(&(client->fd));
			return -1;
		}
		break;
	default:
		warn_msg("AFU device type '%c' is not valid\n", afu_type);
		put_bytes(client->fd, 1, &(rc[0]), fp, psl->dbg_id, -1);
		close_socket(&(client->fd));
		return -1;
	}

	// check to see if device is already open
	// lgt - I think I can open any combination of m/s upto max
	if ( afu_type == 'd' /* | afu_type == 'm' */ ) {
		if (psl->client[0] != NULL) {
			warn_msg
			    ("afu%d.%d%c is already open\n",
			     major, minor, afu_type);
			put_bytes(client->fd, 1, &(rc[0]), fp, psl->dbg_id, -1);
			// should I really close the socket in this case?
			close_socket(&(client->fd));
			return -1;
		}
	}

	// Look for open client slot
	// dedicated - client[0] is the only client.
	// afu-directed - is client[0] the master? not necessarily
	assert(psl->max_clients > 0);
	clients = 0;
	context = -1;
	for (i = 0; i < psl->max_clients; i++) {
		if (psl->client[i] != NULL)
			++clients;
		if ((context < 0) && (psl->client[i] == NULL)) {
			client->context = context = i;
			client->state = CLIENT_VALID;
			client->pending = 0;
			psl->client[i] = client;
			break;
		}
	}
	if (context < 0) {
		info_msg("No room for new client on afu%d.%d\n", major, minor);
		put_bytes(client->fd, 1, &(rc[0]), fp, psl->dbg_id, -1);
		close_socket(&(client->fd));
		return -1;
	}

	// Attach to PSL
	// i should point to an open slot
	rc[0] = PSLSE_OPEN;
	rc[1] = context;
	mmio_offset = 0;
	if (psl->mmio->desc.PerProcessPSA & PROCESS_PSA_REQUIRED) {
		mmio_size = psl->mmio->desc.PerProcessPSA & PSA_MASK;
		mmio_size *= FOUR_K;
		mmio_offset = psl->mmio->desc.PerProcessPSA_offset;
		mmio_offset += mmio_size * i;
	} else {
		mmio_size = MMIO_FULL_RANGE;
	}
	client->mmio_size = mmio_size;
	client->mmio_offset = mmio_offset;
	client->max_irqs = PSL_MAX_IRQS / psl->mmio->desc.num_of_processes;
	client->type = afu_type;

	// Send reset to AFU, if no other clients already connected
	// hmmm...  this might be a problem...
	// I need only do this on the very first client in m/s mode...
	// if this is dedicated client (only one), send a reset
	// if this an an afu-directed client, only send a reset on the very first open...
	// don't even send a reset if we've dropped to 0 clients and are now opening a new one
	switch ( afu_type ) {
	case 'd':
	        // send a reset
	        debug_msg( "_client_associate: adding reset for open of dedicated device", afu_type );
		add_job(psl->job, PSL_JOB_RESET, 0L);
		// ignores psl->has_been_reset
		break;
	case 'm':
	case 's':
	        // send a reset the very first time we associate a client
	        if ( psl->has_been_reset == 0 ) {
		  debug_msg( "_client_associate: adding reset for first open of afu-directed device", afu_type );
		  add_job(psl->job, PSL_JOB_RESET, 0L);
		  psl->has_been_reset = 1;
		}
	        break;
	default:
	        debug_msg( "_client_associate: invalid afu_type: %c", afu_type );
	}

	// Acknowledge to client
	if (put_bytes(client->fd, 2, &(rc[0]), fp, psl->dbg_id, context) < 0) {
		close_socket(&(client->fd));
		return -1;
	}
	debug_context_add(fp, psl->dbg_id, context);

	return 0;
}

static void *_client_loop(void *ptr)
{
	struct client *client = (struct client *)ptr;
	uint8_t data[2];
	int rc;

	pthread_mutex_lock(&lock);
	while (client->pending) {
		rc = bytes_ready(client->fd, client->timeout, &(client->abort));
		if (rc == 0) {
			lock_delay(&lock);
			continue;
		}
		if ((rc < 0) || get_bytes(client->fd, 1, data, 10,
					  &(client->abort), fp, -1, -1) < 0) {
			client_drop(client, PSL_IDLE_CYCLES, CLIENT_NONE);
			break;
		}
		if (data[0] == PSLSE_QUERY) {
			if (get_bytes_silent(client->fd, 1, data, timeout,
					     &(client->abort)) < 0) {
			        debug_msg("_client_loop failed PSLSE_QUERY");
				client_drop(client, PSL_IDLE_CYCLES,
					    CLIENT_NONE);
				break;
			}
			_query(client, data[0]);
			lock_delay(&lock);
			continue;
		}
		if (data[0] == PSLSE_MAX_INT) {
			if (get_bytes(client->fd, 2, data, timeout,
				      &(client->abort), fp, -1, -1) < 0) {
				client_drop(client, PSL_IDLE_CYCLES,
					    CLIENT_NONE);
				break;
			}
			_max_irqs(client, data[0]);
			lock_delay(&lock);
			continue;
		}
		if (data[0] == PSLSE_OPEN) {
			if (get_bytes_silent(client->fd, 2, data, timeout,
					     &(client->abort)) < 0) {
				client_drop(client, PSL_IDLE_CYCLES,
					    CLIENT_NONE);
				debug_msg("_client_loop: client associate failed; could not communicate with socket");
				break;
			}
			_client_associate(client, data[0], (char)data[1]);
			debug_msg("_client_loop: client associated");
			break;
		}
		client->pending = 0;
		break;
		lock_delay(&lock);
	}
	pthread_mutex_unlock(&lock);

	// Terminate thread
	pthread_exit(NULL);
}

static int _start_server()
{
	struct sockaddr_in serv_addr;
	int listen_fd, port, bound, yes;
	char hostname[MAX_LINE_CHARS];

	// Start server
	port = 16384;
	bound = 0;
	listen_fd = -1;
	yes = 1;
	memset(&serv_addr, 0, sizeof(serv_addr));
	listen_fd = socket(AF_INET, SOCK_STREAM, 0);
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	while (!bound) {
		serv_addr.sin_port = htons(port);
		if (setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &yes,
			       sizeof(int)) < 0) {
			perror("setsockopt");
			return -1;
		}
		if (bind(listen_fd, (struct sockaddr *)&serv_addr,
			 sizeof(serv_addr)) < 0) {
			if (errno != EADDRINUSE) {
				perror("bind");
				return -1;
			}
			if (port == 0xFFFF) {
				perror("bind");
				return -1;
			}
			debug_msg("_start_server: Bumping port count");
			++port;
			continue;
		}
		bound = 1;
	}
	listen(listen_fd, 4);	// FIXME: constant 4
	hostname[MAX_LINE_CHARS - 1] = '\0';
	gethostname(hostname, MAX_LINE_CHARS - 1);
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
	char *parms_path;
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

	// Report version
	info_msg("PSLSE version %d.%03d compiled @ %s %s", PSLSE_VERSION_MAJOR,
		 PSLSE_VERSION_MINOR, __DATE__, __TIME__);
	debug_send_version(fp, PSLSE_VERSION_MAJOR, PSLSE_VERSION_MINOR);

	// Parse parameters file
	parms_path = getenv("PSLSE_PARMS")
	if (!parms_path) parms_path = "pslse.parms";
	parms = parse_parms(parms_path, fp);
	if (parms == NULL) {
		error_msg("Unable to parse params file \"%s\"", parms_path);
		return -1;
	}
	timeout = parms->timeout;

	// Connect to simulator(s) and start psl thread(s)
	pthread_mutex_init(&lock, NULL);
	pthread_mutex_lock(&lock);
	afu_map = parse_host_data(&psl_list, parms, "shim_host.dat", &lock, fp);
	if (psl_list == NULL) {
		free(parms);
		fclose(fp);
		warn_msg("Unable to connect to any simulators");
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
		pthread_mutex_unlock(&lock);
		connect_fd = accept(listen_fd, (struct sockaddr *)&client_addr,
				    &client_len);
		pthread_mutex_lock(&lock);
		if (connect_fd < 0) {
			lock_delay(&lock);
			continue;
		}
		ip = (char *)malloc(INET_ADDRSTRLEN + 1);
		inet_ntop(AF_INET, &(client_addr.sin_addr.s_addr), ip,
			  INET_ADDRSTRLEN);
		// Clean up disconnected clients
		client_ptr = &client_list;
		while (*client_ptr != NULL) {
			client = *client_ptr;
			if ((client->pending == 0)
			    && (client->state == CLIENT_NONE)) {
				*client_ptr = client->_next;
				if (client->_next != NULL)
					client->_next->_prev = client->_prev;
				_free_client(client);
				lock_delay(&lock);
				continue;
			}
			client_ptr = &((*client_ptr)->_next);
		}
		// Add new client
		info_msg("Connection from %s", ip);
		client = _client_connect(&connect_fd, ip);
		if (client != NULL) {
			if (client_list != NULL)
				client_list->_prev = client;
			client->_next = client_list;
			client_list = client;
			if (pthread_create(&(client->thread), NULL,
					   _client_loop, client)) {
				perror("pthread_create");
				break;
			}
		}
		lock_delay(&lock);
	}
	info_msg("No AFUs connected, Shutting down PSLSE\n");
	close_socket(&listen_fd);

	// Shutdown unassociated client connections
	while (client_list != NULL) {
		client = client_list;
		client_list = client->_next;
		if (client->pending)
			client->pending = 0;
		pthread_mutex_unlock(&lock);
		pthread_join(client->thread, NULL);
		pthread_mutex_lock(&lock);
		close_socket(&(client->fd));
		_free_client(client);
	}
	pthread_mutex_unlock(&lock);

	free(parms);
	fclose(fp);
	pthread_mutex_destroy(&lock);

	return 0;
}
