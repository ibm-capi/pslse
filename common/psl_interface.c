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

#include "psl_interface.h"

#include <arpa/inet.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

/* For PSL out-bound haX parity buses, generate Odd parity bit for a specified
 * data size set */

static uint32_t genoddParitybitperbytes(uint64_t data)
{
	//For odd parity: If sum of data bits is even, parity is 1
	uint32_t oddparity;
	oddparity = 1;		//since odd, start off setting

	// Count off least significant asserted bit
	while (data) {
		oddparity = 1 - oddparity;	// 0->1 or 1->0
		data &= data - 1;	// Remove lsb that is set to 1
	}

	return oddparity;
}

static void set_protocol_level(struct AFU_EVENT *event, uint32_t primary,
			       uint32_t secondary, uint32_t tertiary)
{
		printf("PSL_SOCKET:\tEntering set_protocol_level.\n");
	if ((event->proto_primary != primary) ||
	    (event->proto_secondary != secondary) ||
	    (event->proto_tertiary != tertiary)) {
		printf( "PSL_SOCKET:WARNING: Adjusting PSL interface protocol level!\n");
		printf( "PSL_SOCKET:\tPlease review changes between levels.\n");
		printf( "PSL_SOCKET:\tSupported PSL protocol level: %d.%d.%d\n",
		       event->proto_primary, event->proto_secondary,
		       event->proto_tertiary);
	}
	event->proto_primary = primary;
	event->proto_secondary = secondary;
	event->proto_tertiary = tertiary;
}

static int establish_protocol(struct AFU_EVENT *event)
{
	int bc, bl, bp, i;
	bp = 0;
	bl = 16;
	fd_set watchset;	/* fds to read from */
	uint8_t byte;
	uint32_t primary, secondary, tertiary;

	// Send protocol ID to other side of socket connection
	event->tbuf[0] = 'P';
	event->tbuf[1] = 'S';
	event->tbuf[2] = 'L';
	event->tbuf[3] = '\0';
	for (i = 0; i < 4; i++) {
		event->tbuf[4 + i] =
		    ((event->proto_primary) >> ((3 - i) * 8)) & 0xFF;
	}
	for (i = 0; i < 4; i++) {
		event->tbuf[8 + i] =
		    ((event->proto_secondary) >> ((3 - i) * 8)) & 0xFF;
	}
	for (i = 0; i < 4; i++) {
		event->tbuf[12 + i] =
		    ((event->proto_tertiary) >> ((3 - i) * 8)) & 0xFF;
	}
	while (bp < bl) {
		bc = send(event->sockfd, event->tbuf + bp, bl - bp, 0);
		if (bc < 0) {
			fprintf(stderr, "ERROR: establish_protocol: send failed: %s\n",
							strerror(errno));
			return PSL_TRANSMISSION_ERROR;
		}
		bp += bc;
	}

	// Get protocol ID from other side of socket connection
	bc = 0;
	FD_ZERO(&watchset);
	FD_SET(event->sockfd, &watchset);
	select(event->sockfd + 1, &watchset, NULL, NULL, NULL);
	while ((event->rbp < 16) && (bc != -1)) {
		if ((bc =
		     recv(event->sockfd, &(event->rbuf[event->rbp]), 1,
			  0)) == -1) {
			if (errno == EWOULDBLOCK) {
				select(event->sockfd + 1, &watchset, NULL, NULL,
				       NULL);
				continue;
			} else {
				return PSL_BAD_SOCKET;
			}
		}
		event->rbp += bc;
	}
	event->rbp = 0;

	if (strcmp((char *)event->rbuf, "PSL") != 0) {
		if (strcmp((char *)event->rbuf, "PSLSE") == 0) {
			fprintf(stderr, "ERROR: establish_protocol: PSLSE client attempted"
							" to connect directly, instead of relaying through the"
							" pslse server.\n");
		} else {
			fprintf(stderr, "ERROR: establish_protocol: Unrecognized protocol.\n");
		}
		return PSL_BAD_SOCKET;
	}

	primary = 0;
	for (i = 4; i < 8; i++) {
		byte = event->rbuf[i];
		primary <<= 8;
		primary += (uint32_t) byte;
	}

	secondary = 0;
	for (i = 8; i < 12; i++) {
		byte = event->rbuf[i];
		secondary <<= 8;
		secondary += (uint32_t) byte;
	}

	tertiary = 0;
	for (i = 12; i < 16; i++) {
		byte = event->rbuf[i];
		tertiary <<= 8;
		tertiary += (uint32_t) byte;
	}

	// Check for broken levels
	if ((primary == 0) && (secondary == 9908) && (tertiary == 0)) {
		printf("Remote psl_interface code using broken code level!\n");
		printf("\tLocal psl_interface level:%d.%d.%d\n",
		       event->proto_primary, event->proto_secondary,
		       event->proto_tertiary);
		printf("\tRemote psl_interface level:%d.%d.%d\n",
		       primary, secondary, tertiary);
		return PSL_BAD_SOCKET;
	}
	
	// Check for mis-matched primary level and error out if found
	if (primary != event->proto_primary) {
		printf("ERROR: Remote psl_interface code using different PSL revision level!!\n");
		printf("\tLocal psl_interface level:%d.%d.%d\n",
		       event->proto_primary, event->proto_secondary,
		       event->proto_tertiary);
		printf("\tRemote psl_interface level:%d.%d.%d\n",
		       primary, secondary, tertiary);
		printf("Please check your #define setting in common/psl_interface_t.h!!\n");
		printf("Please recompile libcxl, pslse, your AFU and your application before rerunning!!\n");
		return PSL_VERSION_ERROR;
	}
	else 
		return PSL_SUCCESS;


         /* comment out for now
	// Test if other side with adjust protocol level down
	if (primary > event->proto_primary)
		return PSL_SUCCESS;
	if (secondary > event->proto_secondary)
		return PSL_SUCCESS;
	if (tertiary > event->proto_tertiary)
		return PSL_SUCCESS;

        // Adjust protocol level down on this side if neccesary
	if (primary < event->proto_primary)
		set_protocol_level(event, primary, secondary, tertiary);
	else if (secondary < event->proto_secondary)
		set_protocol_level(event, primary, secondary, tertiary);
	else if (tertiary < event->proto_tertiary)
		set_protocol_level(event, primary, secondary, tertiary);

	return PSL_SUCCESS; */
}

/* Call this at startup to reset all the event indicators */

void psl_event_reset(struct AFU_EVENT *event)
{
	memset(event, 0, sizeof(*event));
	event->proto_primary = PROTOCOL_PRIMARY;
	event->proto_secondary = PROTOCOL_SECONDARY;
	event->proto_tertiary = PROTOCOL_TERTIARY;
}

/* Call this once after creation to initialize the AFU_EVENT structure and
 * open a socket conection to an AFU server.  This function initializes the
 * PSL side of the interface which is the client in the socket connection
 * server_host should be the name of the server hosting the simulation of
 * the AFU and port is the active port on that server. */

int psl_init_afu_event(struct AFU_EVENT *event, char *server_host, int port)
{
	psl_event_reset(event);
	event->room = 64;
	event->rbp = 0;
	struct hostent *he;
	if ((he = gethostbyname(server_host)) == NULL) {
		herror("gethostbyname");
		return PSL_BAD_SOCKET;
	}
	struct sockaddr_in ssadr;
	memset(&ssadr, 0, sizeof(ssadr));
	memcpy(&ssadr.sin_addr, he->h_addr_list[0], he->h_length);
	ssadr.sin_family = AF_INET;
	ssadr.sin_port = htons(port);
	event->sockfd = socket(PF_INET, SOCK_STREAM, 0);
	if (event->sockfd == 0) {
		perror("socket");
		return PSL_BAD_SOCKET;
	}
	if (connect(event->sockfd, (struct sockaddr *)&ssadr, sizeof(ssadr)) <
	    0) {
		perror("connect");
		return PSL_BAD_SOCKET;
	}
	fcntl(event->sockfd, F_SETFL, O_NONBLOCK);

	int rc = establish_protocol(event);
	printf("PSL_SOCKET: Using PSL protocol level : %d.%d.%d\n",
	       event->proto_primary, event->proto_secondary,
	       event->proto_tertiary);

	return rc;
}

/* Call this to close the socket connection from either side */

int psl_close_afu_event(struct AFU_EVENT *event)
{
	char buffer[4096];

	// Shutdown socket traffic
	if (shutdown(event->sockfd, SHUT_RDWR))
		return PSL_CLOSE_ERROR;

	// Drain any data in socket
	while (recv(event->sockfd, buffer, sizeof(buffer) - 1, MSG_DONTWAIT) >
	       0) ;

	// Close socket
	if (close(event->sockfd))
		return PSL_CLOSE_ERROR;
	event->sockfd = -1;

	return PSL_SUCCESS;
}

/* Call this once after creation to initialize the AFU_EVENT structure. */
/* This function initializes the AFU side of the interface which is the
 * server in the socket connection. */

int psl_serv_afu_event(struct AFU_EVENT *event, int port)
{
	int cs = -1;
	psl_event_reset(event);
	event->room = 64;
	event->rbp = 0;
#ifdef PSL9
	event->dma0_wr_credits = MAX_DMA0_WR_CREDITS;
	event->dma0_rd_credits = MAX_DMA0_RD_CREDITS;
        //printf("psl_serv_afu_event: rd_credit count is %d  wr_credit count is %d \n", event->dma0_rd_credits, event->dma0_wr_credits);
#endif 
	struct sockaddr_in ssadr, csadr;
	unsigned int csalen = sizeof(csadr);
	memset(&ssadr, 0, sizeof(ssadr));
	ssadr.sin_family = AF_UNSPEC;
	ssadr.sin_addr.s_addr = INADDR_ANY;
	ssadr.sin_port = htons(port);
	event->sockfd = socket(PF_INET, SOCK_STREAM, 0);
	if (event->sockfd < 0) {
		perror("socket");
		return PSL_BAD_SOCKET;
	}
	if (bind(event->sockfd, (struct sockaddr *)&ssadr, sizeof(ssadr)) == -1) {
		perror("bind");
		psl_close_afu_event(event);
		return PSL_BAD_SOCKET;
	}
	char hostname[1024];
	hostname[1023] = '\0';
	gethostname(hostname, 1023);
	printf("AFU Server is waiting for connection on %s:%d\n", hostname,
	       port);
	fflush(stdout);
	if (listen(event->sockfd, 10) == -1) {
		perror("listen");
		psl_close_afu_event(event);
		return PSL_BAD_SOCKET;
	}
	while (cs < 0) {
		cs = accept(event->sockfd, (struct sockaddr *)&csadr, &csalen);
		if ((cs < 0) && (errno != EINTR)) {
			perror("accept");
			psl_close_afu_event(event);
			return PSL_BAD_SOCKET;
		}
	}
	close(event->sockfd);
	event->sockfd = cs;
	fcntl(event->sockfd, F_SETFL, O_NONBLOCK);
	char clientname[1024];
	clientname[1023] = '\0';
	getnameinfo((struct sockaddr *)&csadr, sizeof(csadr), clientname, 1024,
		    NULL, 0, 0);
	printf("PSL client connection from %s\n", clientname);

	int rc = establish_protocol(event);
	printf("Using PSL protocol level : %d.%d.%d\n", event->proto_primary,
	       event->proto_secondary, event->proto_tertiary);

	return rc;
}

/* Call this to change auxilliary signals (room) */

int psl_aux1_change(struct AFU_EVENT *event, uint32_t room)
{
	if (event->aux1_change) {
		return PSL_DOUBLE_COMMAND;
	} else {
		event->aux1_change = 1;
		event->room = room;
		return PSL_SUCCESS;
	}
}

/* Call this to create an accelerator control command */

int
psl_job_control(struct AFU_EVENT *event, uint32_t job_code, uint64_t address)
{
	if (event->job_valid) {
		return PSL_DOUBLE_COMMAND;
	} else {
		event->job_valid = 1;
		event->job_code = job_code;
		event->job_address = address;
		event->job_code_parity =
		    genoddParitybitperbytes((uint64_t) job_code);
		event->job_address_parity = genoddParitybitperbytes(address);
		return PSL_SUCCESS;
	}
}

/* Call this to create an MMIO read command. If the dbl argument is 1, 64 bits
 * are transferred.  If it is 0, 32 bits are transferred */

int
psl_mmio_read(struct AFU_EVENT *event,
	      uint32_t dbl, uint32_t address, uint32_t afudescaccess)
{
	if (event->mmio_valid) {
		return PSL_DOUBLE_COMMAND;
	} else {
		event->mmio_valid = 1;
		event->mmio_read = 1;
		event->mmio_double = dbl;
		event->mmio_address = address;
		event->mmio_address_parity = genoddParitybitperbytes(address);
		event->mmio_afudescaccess = afudescaccess;
		return PSL_SUCCESS;
	}
}

/* Call this to create an MMIO write command. If the dbl argument is 1, 64 bits
 * are transferred.  If it is 0, 32 bits are transferred (least significant
 * 32 bits of write_data. */

int
psl_mmio_write(struct AFU_EVENT *event,
	       uint32_t dbl,
	       uint32_t address, uint64_t write_data, uint32_t afudescaccess)
{
	if (event->mmio_valid) {
		return PSL_DOUBLE_COMMAND;
	} else {
		event->mmio_valid = 1;
		event->mmio_read = 0;
		event->mmio_double = dbl;
		event->mmio_address = address;
		event->mmio_address_parity = genoddParitybitperbytes(address);
		event->mmio_wdata = write_data;
		event->mmio_wdata_parity = genoddParitybitperbytes(write_data);
		event->mmio_afudescaccess = afudescaccess;
		return PSL_SUCCESS;
	}
}

/* Call this to create a command response */

int
psl_response(struct AFU_EVENT *event,
	     uint32_t tag,
	     uint32_t response_code,
#if defined PSL9 || defined PSL9lite
	     int credits, uint32_t cache_state, uint32_t cache_position, uint32_t pagesize, uint32_t resp_extra)
#else
	     int credits, uint32_t cache_state, uint32_t cache_position)
#endif
{
	(void)tag;
	if (event->response_valid) {
		return PSL_DOUBLE_COMMAND;
	} else {
		event->response_valid = 1;
		event->response_tag = tag;
		event->response_tag_parity = genoddParitybitperbytes(tag);
		event->response_code = response_code;
		event->credits = credits;
		event->cache_state = cache_state;
		event->cache_position = cache_position;
#if defined PSL9 || defined PSL9lite
		event->response_r_pgsize = pagesize;
		event->response_extra = resp_extra;
#endif
		return PSL_SUCCESS;
	}
}

/* Call this to read a buffer */
/* Length must be either 64 or 128 which is the transfer size in bytes.
 * For 64B transfers, only the first half of the array is used */

int
psl_buffer_read(struct AFU_EVENT *event,
		uint32_t tag, uint64_t address, uint32_t length)
{
	if (event->buffer_read) {
		return PSL_DOUBLE_COMMAND;
	} else {
		event->buffer_read = 1;
		event->buffer_read_tag = tag;
		event->buffer_read_tag_parity = genoddParitybitperbytes(tag);
		event->buffer_read_address = address;
		event->buffer_read_length = length;
		return PSL_SUCCESS;
	}
}

/* Call this to write a buffer, write_data is a 32 element array of 32-bit
 * values, write_parity is a 4 element array of 32-bit values.
 * Length must be either 64 or 128 which is the transfer size in bytes.
 * For 64B transfers, only the first half of the array is used */

int
psl_buffer_write(struct AFU_EVENT *event,
		 uint32_t tag,
		 uint64_t address,
		 uint32_t length, uint8_t * write_data, uint8_t * write_parity)
{
	if (event->buffer_write) {
		return PSL_DOUBLE_COMMAND;
	} else {
		event->buffer_write = 1;
		event->buffer_write_tag = tag;
		event->buffer_write_tag_parity = genoddParitybitperbytes(tag);
		event->buffer_write_address = address;
		event->buffer_write_length = length;
		memcpy(event->buffer_wdata, write_data, length);
		memcpy(event->buffer_wparity, write_parity, length / 64);
		return PSL_SUCCESS;
	}
}

#ifdef PSL9
/* Call this to write a dma port completion bus
 * For DMA returns, 128B max returned per cycle
 * For AMO returns, cpl_size is only 4 or 8. */

int
psl_dma0_cpl_bus_write(struct AFU_EVENT *event,
		 uint32_t utag,
		 uint32_t dsize,
		 uint32_t cpl_type,
		 uint32_t cpl_size, 
		 uint32_t cpl_laddr,
		 uint32_t cpl_byte_count, uint8_t * write_data)
{
	//if ((event->dma0_completion_valid) || (event->dma0_sent_utag_valid)) {
	if (event->dma0_completion_valid)  {
	printf("IN DMA0_CPL_BUS_WRITE AND DOUBLE CMD!!!\n");
		return PSL_DOUBLE_COMMAND;
	} else {
		event->dma0_completion_valid = 1;
		event->dma0_completion_utag = utag;
		event->dma0_completion_type = cpl_type;
		event->dma0_completion_size = cpl_size;
		event->dma0_completion_laddr = cpl_laddr;
		event->dma0_completion_byte_count = cpl_byte_count;
		//printf(" IN PSL_DMA0_CPL_BUS_WRITE and cpl_laddr is ox%3x and cpl_byte_count is 0x%3x\n", cpl_laddr, cpl_byte_count);
		// is this a multi cycle transaction? check cpl_byte_count
		if (cpl_byte_count > 128)   {
			if ((384 < dsize) && (dsize <= 512) && (cpl_size == cpl_byte_count))  { // our second multi cycle completion pass
				if (cpl_type == 0)
					memcpy(event->dma0_completion_data, &(write_data[256]), 128);
				if (cpl_type == 1)
					memcpy(event->dma0_completion_data, &(write_data[384]), cpl_size - 128);
			} else {  // our first multi cycle completion (128 < dsize <= 384)
				if (cpl_type == 0)
					memcpy(event->dma0_completion_data, write_data, 128);
				if (cpl_type == 1)
					memcpy(event->dma0_completion_data, &(write_data[128]), cpl_size - 128);
				}
		} else  {	// cpl_byte_count <= 128 so just single cycle (128 <= dsize OR last compl for <= 384B )
				if (dsize > 256)
					memcpy(event->dma0_completion_data, &(write_data[256]), cpl_size);
				else
					memcpy(event->dma0_completion_data, write_data, cpl_size);
			}
		return PSL_SUCCESS;
	}
}

/* Call this to write a dma port utag sent back on the DMA bus. */

int
psl_dma0_sent_utag(struct AFU_EVENT *event,
		 uint32_t utag,
		 uint32_t sent_sts)
{
	if (event->dma0_sent_utag_valid) {
		return PSL_DOUBLE_COMMAND;
	} else {
		event->dma0_sent_utag_valid = 1;
		event->dma0_sent_utag = utag;
		event->dma0_sent_utag_status = sent_sts;
		return PSL_SUCCESS;
	}
}


/* Call this to read dma0 data bus and associated signals */
int
psl_get_dma0_port(struct AFU_EVENT *event,
		uint32_t  * utag,
		uint32_t  * itag,
		uint32_t  * type,
		uint32_t  * size,
		uint32_t  * atomic_op,
		uint32_t * atomic_le,
		uint8_t * dma0_req_data ) 
{
	if (event->dma0_dvalid == 0)
		return 1;
	else {
		*utag = event->dma0_req_utag;
		*itag = event->dma0_req_itag;
		*type = event->dma0_req_type;
		*size = event->dma0_req_size;
		*atomic_op = event->dma0_atomic_op;
		*atomic_le = event->dma0_atomic_le;

		if (event->dma0_req_type == DMA_DTYPE_ATOMIC)   
			memcpy(dma0_req_data, event->dma0_req_data, 16);
		if (event->dma0_req_type == DMA_DTYPE_WR_REQ_128) { 
			if (event->dma0_req_size <= 128)  {
				memcpy(dma0_req_data, event->dma0_req_data, event->dma0_req_size);
			} else { //the start of a >128B write operation
				memcpy(dma0_req_data, event->dma0_req_data, 128);
			}
		}
 		if (event->dma0_req_type == DMA_DTYPE_WR_REQ_MORE)  { 
			if (event->dma0_wr_partial <= 128) 
				memcpy(dma0_req_data, event->dma0_req_data, event->dma0_wr_partial);
			else {
				memcpy(dma0_req_data, event->dma0_req_data, 128);
			}
		}

		}
		event->dma0_dvalid = 0;
	//printf ("leaving psl_get_dma0_port and setting dma0_dvalid to 0\n");
		return PSL_SUCCESS;
}
	
#endif /* ifdef PSL9 */


/* Call after an event is received from the AFU to see if previous MMIO
 * operation has been acknowledged and extract read MMIO data if available. */

int
psl_get_mmio_acknowledge(struct AFU_EVENT *event,
			 uint64_t * read_data, uint32_t * read_data_parity)
{
	if (!event->mmio_ack) {
		return PSL_MMIO_ACK_NOT_VALID;
	} else {
		event->mmio_ack = 0;
		event->mmio_valid = 0;
		*read_data = event->mmio_rdata;
		*read_data_parity = event->mmio_rdata_parity;
		return PSL_SUCCESS;
	}
}

/* Call after an event is received from the AFU to see if any of the auxilliary
 * signals have changed values */

int
psl_get_aux2_change(struct AFU_EVENT *event,
		    uint32_t * job_running,
		    uint32_t * job_done,
		    uint32_t * job_cack_llcmd,
		    uint64_t * job_error,
		    uint32_t * job_yield,
		    uint32_t * tb_request,
		    uint32_t * par_enable, uint32_t * read_latency)
{
	if (!event->aux2_change) {
		return PSL_AUX2_NOT_VALID;
	} else {
		event->aux2_change = 0;
		*job_running = event->job_running;
		*job_done = event->job_done;
		*job_cack_llcmd = event->job_cack_llcmd;
		*job_error = event->job_error;
		*job_yield = event->job_yield;
		*tb_request = event->timebase_request;
		*par_enable = event->parity_enable;
		*read_latency = event->buffer_read_latency;
		return PSL_SUCCESS;
	}
}

/* Call after an event is received from the AFU to extract read buffer data if
 * available. read_data is a 32 element array of 32-bit values, read_parity is
 * a 4 element array of 32-bit values.
 * Note: fields in AFU_EVENT structre can also be accessed directly */

int
psl_get_buffer_read_data(struct AFU_EVENT *event,
			 uint8_t * read_data, uint8_t * read_parity)
{
	if (!event->buffer_rdata_valid) {
		return PSL_BUFFER_READ_DATA_NOT_VALID;
	} else {
		event->buffer_rdata_valid = 0;
		event->buffer_read = 0;
		memcpy(read_data, event->buffer_rdata,
		       sizeof(event->buffer_rdata));
		memcpy(read_parity, event->buffer_rparity,
		       sizeof(event->buffer_rparity));
		return PSL_SUCCESS;
	}
}

/* Call after an event is received from the AFU to extract a PSL command
 * if available.
 * Note: fields in AFU_EVENT structre can also be accessed directly */

int
psl_get_command(struct AFU_EVENT *event,
		uint32_t * command,
		uint32_t * command_parity,
		uint32_t * tag,
		uint32_t * tag_parity,
		uint64_t * address,
		uint64_t * address_parity,
#if defined PSL9 || defined PSL9lite
		uint32_t * size, uint32_t * abort, uint32_t * handle, uint32_t * cpagesize)
#else
		uint32_t * size, uint32_t * abort, uint32_t * handle)
#endif
{
	if (!event->command_valid) {
		//if (event->dma0_dvalid)
			//printf ("NO VALID CMD BUT DMA0_DVALID with itag=0x%x and type=0x%x\n", event->dma0_req_itag, event->dma0_req_type);
		return PSL_COMMAND_NOT_VALID;
	} else {
		event->command_valid = 0;
		*command = event->command_code;
		*command_parity = event->command_code_parity;
		*address = event->command_address;
		*address_parity = event->command_address_parity;
		*tag = event->command_tag;
		*tag_parity = event->command_tag_parity;
		*size = event->command_size;
		*abort = event->command_abort;
		*handle = event->command_handle;
#if defined PSL9 || defined PSL9lite
		*cpagesize  = event-> command_cpagesize;
#endif
		return PSL_SUCCESS;
	}
}

/* Call this to send an event to the AFU model after calling one or more of:
 * psl_aux1_change, psl_job_control, psl_mmio_read, psl_mmio_write,
 * psl_response, psl_buffer_read, psl_buffer_write */

int psl_signal_afu_model(struct AFU_EVENT *event)
{
        int i, bc, bl, bytes_to_xfer;
	int bp = 1;
	if (event->clock != 0)
		return PSL_TRANSMISSION_ERROR;
	event->clock = 1;
	event->tbuf[0] = 0x40;
#ifdef PSL9
	if (event->dma0_completion_valid != 0) {
		event->tbuf[0] = event->tbuf[0] | 0x80;
		// printf("event->tbuf[0] is 0x%2x \n", event->tbuf[0]);
		// need to have size as second/third byte for RX side to easily access for rbc
		event->tbuf[bp++] = ((event->dma0_completion_size) >> 8) | 0x30;
		// printf("event->tbuf[%x] is 0x%2x \n", bp-1, event->tbuf[bp-1]);
		//upper 4 bits in second byte are b0011 to indicate this transaction is dma0_completion
		// NOTE - read transactions can never be greater than 128bytes per cycle
		//printf("event->dma0_completion_size is 0x%03x \n", event->dma0_completion_size);
		//printf("event->dma0_completion_type is 0x%03x \n", event->dma0_completion_type);
		//printf("event->dma0_completion_utag is 0x%03x \n", event->dma0_completion_utag);
		//printf("event->dma0_completion_laddr is 0x%03x \n", event->dma0_completion_laddr);
		//printf("event->dma0_completion_byte_count is 0x%03x \n", event->dma0_completion_byte_count);
		event->tbuf[bp++] = (event->dma0_completion_size & 0xFF);
		//printf("event->tbuf[%x] is 0x%2x \n", bp-1, event->tbuf[bp-1]);
		event->tbuf[bp++] = ((event->dma0_completion_utag >> 8) & 0x03);
		event->tbuf[bp-1] = (event->tbuf[bp-1] | ((event->dma0_completion_type) << 4) );
		//printf("event->tbuf[%x] is 0x%2x  \n", bp-1, event->tbuf[bp-1]);
		event->tbuf[bp++] = (event->dma0_completion_utag & 0xFF);
		//printf("event->tbuf[%x] is 0x%2x  \n", bp-1, event->tbuf[bp-1]);
		event->tbuf[bp++] = (event->dma0_completion_laddr & 0xFF);
		//printf("event->tbuf[%x] is 0x%2x  \n", bp-1, event->tbuf[bp-1]);
		event->tbuf[bp++] = (event->dma0_completion_byte_count & 0xFF);
		//printf("event->tbuf[%x] is 0x%2x  \n", bp-1, event->tbuf[bp-1]);
		event->tbuf[bp++] = ((event->dma0_completion_byte_count >> 8) | 
					((event->dma0_completion_laddr & 0x0300) >> 4));
		//printf("event->tbuf[%x] is 0x%2x \n", bp-1, event->tbuf[bp-1]);
		if (event->dma0_completion_byte_count > 128)   {
			if (event->dma0_completion_type == 0)
				bytes_to_xfer = 128;
			if (event->dma0_completion_type == 1)
				bytes_to_xfer = (event->dma0_completion_size - 128);
		} else  // cpl_byte_count <= 128 so just single cycle
			bytes_to_xfer = event->dma0_completion_size;
		for (i = 0; i < bytes_to_xfer; i++) {
			event->tbuf[bp++] = event->dma0_completion_data[i];
		//printf("x%2x ",  event->tbuf[bp-1]);
		}
		event->dma0_completion_valid = 0;
	}
	if (event->dma0_sent_utag_valid != 0) {
		event->tbuf[0] = event->tbuf[0] | 0x80;
		//printf("event->tbuf[0] is 0x%2x \n", event->tbuf[0]);
		event->tbuf[bp++] = (event->dma0_sent_utag_status  & 0x03 );
		// make sure that upper 4 bits of tbuf[1]  are b1100, as this transaction is dma0_sent_utag
		event->tbuf[1] = (event->tbuf[1]  | 0xC0 );
		//printf("event->dma0_sent_utag_status is 0x%2x  \n", event->dma0_sent_utag_status);
		//printf("event->dma0_sent_utag is 0x%2x  \n", event->dma0_sent_utag);
		//event->tbuf[bp-1] = event->tbuf[bp-1] | 0xC0;
		//printf("event->tbuf[1] is 0x%2x  \n", event->tbuf[1]);
		//printf("event->tbuf[bp] is 0x%2x and bp is 0x%2x \n", event->tbuf[bp], bp);
		event->tbuf[bp++] = ((event->dma0_sent_utag >> 8) & 0x03);
		//printf("event->tbuf[2] is 0x%2x and bp-1 is 0x%2x \n", event->tbuf[2], bp-1);
		event->tbuf[bp++] = (event->dma0_sent_utag & 0x0FF);
		//printf("event->tbuf[3] is 0x%2x and bp-1 is 0x%2x \n", event->tbuf[3], bp-1);
		event->dma0_sent_utag_valid = 0;
	}
#endif 
	if (event->aux1_change != 0) {
		event->tbuf[0] = event->tbuf[0] | 0x20;
		event->tbuf[bp++] = event->room;
		event->aux1_change = 0;
	}
	if (event->job_valid != 0) {
		event->tbuf[0] = event->tbuf[0] | 0x10;
		event->tbuf[bp++] = event->job_code;
		for (i = 0; i < 8; i++) {
			event->tbuf[bp++] =
			    ((event->job_address) >> ((7 - i) * 8)) & 0xFF;
		}
		event->tbuf[bp++] = (((event->job_address_parity) << 1) & 0x2) |
		    ((event->job_code_parity) & 0x1);
		event->job_valid = 0;
	}
	if (event->mmio_valid != 0) {
		event->tbuf[0] = event->tbuf[0] | 0x08;
		if (event->mmio_read != 0) {
			event->tbuf[bp] = 0x01;
		} else {
			event->tbuf[bp] = 0x00;
		}
		if (event->mmio_double != 0) {
			event->tbuf[bp] = event->tbuf[bp] | 0x02;
		}
		if (event->mmio_afudescaccess != 0) {
			event->tbuf[bp] = event->tbuf[bp] | 0x04;
		}
		if (event->mmio_address_parity != 0) {
			event->tbuf[bp] = event->tbuf[bp] | 0x08;
		}
		if (event->mmio_wdata_parity != 0) {
			event->tbuf[bp] = event->tbuf[bp] | 0x10;
		}
		bp++;
		for (i = 0; i < 3; i++) {
			event->tbuf[bp++] =
			    ((event->mmio_address) >> ((2 - i) * 8)) & 0xFF;
		}
		for (i = 0; i < 8; i++) {
			event->tbuf[bp++] =
			    ((event->mmio_wdata) >> ((7 - i) * 8)) & 0xFF;
		}
		event->mmio_valid = 0;
	}
	if (event->response_valid != 0) {
	      //  printf( "lgt: psl_signal_afu_model: response: tag=0x%02x, tag parity=0x%02x, code=0x%02x \n", 
		//	event->response_tag, 
		//	event->response_tag_parity, 
		//	event->response_code);
		event->tbuf[0] = event->tbuf[0] | 0x04;
		event->tbuf[bp++] = event->response_tag;
		event->tbuf[bp++] = event->response_tag_parity;
		event->tbuf[bp++] = event->response_code;
		event->tbuf[bp++] = ((event->cache_position) >> 5) & 0xFF;
		event->tbuf[bp++] = ((event->cache_position) << 3) |
		    (((event->cache_state) << 1) & 0x6) |
		    (((event->credits) >> 8) & 1);
		event->tbuf[bp++] = event->credits & 0xFF;
#ifdef PSL9
		event->tbuf[bp++] = (((event->response_dma0_itag & 0x100) >> 8) | (event->response_dma0_itag_parity  << 4));
		event->tbuf[bp++] = event->response_dma0_itag & 0xFF;
	       // printf( "lgt: psl_signal_afu_model: response: itag=0x%02x,tag=0x%02x \n", 
		//	event->response_dma0_itag, event->response_tag); 
	// eventually may need to add another char for response_ext too
	// for now, we always return the default value for pagesize, set by pslse.parms
		event->tbuf[bp++] = (event->response_r_pgsize & 0x0F);
		event->response_dma0_itag = 0;
		event->response_dma0_itag_parity = 0;
#endif
		event->response_valid = 0;
	}
	if (event->buffer_read != 0) {
	  //printf( "lgt: psl_signal_afu_model: buffer read: tag: 0x%02x, tag parity: 0x%02x\n", 
	  //	event->buffer_read_tag, 
	  //	event->buffer_read_tag_parity);
		event->tbuf[0] = event->tbuf[0] | 0x02;
		event->tbuf[bp++] = event->buffer_read_tag;
		event->tbuf[bp++] = event->buffer_read_tag_parity;
		if (event->buffer_read_length > 64) {
			event->tbuf[bp++] =
			    0x80 | (event->buffer_read_address & 0x3F);
		} else {
			event->tbuf[bp++] =
			    0x00 | (event->buffer_read_address & 0x3F);
		}
		event->buffer_read = 0;
	}
	if (event->buffer_write != 0) {
	  // printf( "lgt: psl_signal_afu_model: buffer write: tag: 0x%02x, tag parity: 0x%02x\n", 
	  //	event->buffer_write_tag, 
	  //	event->buffer_write_tag_parity);
		event->tbuf[0] = event->tbuf[0] | 0x01;
		event->tbuf[bp++] = event->buffer_write_tag;
		event->tbuf[bp++] = event->buffer_write_tag_parity;
		if (event->buffer_write_length > 64) {
			event->tbuf[bp++] =
			    0x80 | (event->buffer_write_address & 0x3F);
		} else {
			event->tbuf[bp++] =
			    0x00 | (event->buffer_write_address & 0x3F);
		}
		for (i = 0; i < 128; i++) {
			event->tbuf[bp++] = event->buffer_wdata[i];
		}
		for (i = 0; i < 2; i++) {
			event->tbuf[bp++] = event->buffer_wparity[i];
		}
		event->buffer_write = 0;


	}

	// dump tbuf
//	if ( bp > 1 ) {
//	  printf( "lgt: psl_signal_afu_model: tbuf length:0x%02x tbuf: 0x", bp ); 
//	  int j;
//	  for ( j = 0; j < bp; j++ ) printf( "%02x", event->tbuf[j] );
//	  printf( "\n" );
//	}

	bl = bp;
	bp = 0;
	while (bp < bl) {
		bc = send(event->sockfd, event->tbuf + bp, bl - bp, 0);
		if (bc < 0)
			return PSL_TRANSMISSION_ERROR;
		bp += bc;
	}
	return PSL_SUCCESS;
}

/* Call this to send an event to the PSL model */
/* UPDATE: Now static as it's called in psl_get_psl_events() */

static int psl_signal_psl_model(struct AFU_EVENT *event)
{
	int i, bc, bl;
	int bp = 1;
	if (event->clock != 1)
		return PSL_SUCCESS;
	event->clock = 0;
	event->tbuf[0] = 0x10;
#ifdef PSL9
	if (event->dma0_dvalid)  {
// dma0 request read or write  
		event->tbuf[0] = event->tbuf[0] | 0x80;
		//printf("utag 0x%3x itag 0x%3x type 0x%2x size 0x%3x  bp 0x%2x \n", 
		//       event->dma0_req_utag, event->dma0_req_itag, event->dma0_req_type, 
		//       event->dma0_req_size, bp);
		//printf("event->dma0_req_type is 0x%2x \n", event->dma0_req_type);
		event->tbuf[bp++] = (event->dma0_req_type ) & 0xFF;
		//printf("event->tbuf[%x] is 0x%2x \n", bp-1, event->tbuf[bp-1]);
		event->tbuf[bp++] = (event->dma0_req_size >> 8 ) & 0x03;
		//printf("event->tbuf[%x] is 0x%2x \n", bp-1, event->tbuf[bp-1]);
		event->tbuf[bp++] = (event->dma0_req_size ) & 0xFF;
		//printf("event->tbuf[%x] is 0x%2x \n", bp-1, event->tbuf[bp-1]);
		//move up the req_aize so other side can determine what to do for dma writes < or > 128B
		// if dtype == 3, then utag is only 8 bits, not 10 - TODO, do we check here? if not, where?
		event->tbuf[bp++] = (event->dma0_req_utag >> 8 ) & 0x03;
		//printf("event->tbuf[0] is 0x%2x \n", event->tbuf[0]);
		//printf("event->tbuf[%x] is 0x%2x \n", bp-1,event->tbuf[bp-1]);
		event->tbuf[bp++] = (event->dma0_req_utag ) & 0xFF;
		//printf("event->tbuf[%x] is 0x%2x \n", bp-1, event->tbuf[bp-1]);
		event->tbuf[bp++] = (event->dma0_req_itag >> 8 ) & 0x01;
		//printf("event->tbuf[%x] is 0x%2x \n", bp-1, event->tbuf[bp-1]);
		event->tbuf[bp++] = (event->dma0_req_itag ) & 0xFF;
		//printf("event->tbuf[%x] is 0x%2x \n", bp-1, event->tbuf[bp-1]);
		//event->tbuf[bp++] = (event->dma0_req_size >> 8 ) & 0x03;
		//printf("event->tbuf[6] is 0x%2x \n", event->tbuf[bp-1]);
		//event->tbuf[bp++] = (event->dma0_req_size ) & 0xFF;
		//printf("event->tbuf[7] is 0x%2x \n", event->tbuf[bp-1]);
		// if type is dma read req, no data to xfer here 
		if (event->dma0_req_type == DMA_DTYPE_WR_REQ_128)  {
		// MAX transfer for DMA is 512B but assumption is socket transfers are <= 128B each
			if (event->dma0_req_size <= 128) {
				bc = event->dma0_req_size;
				event->dma0_wr_partial = 0;   
			} else {
				bc = 128;
				//event->dma0_wr_partial = event->dma0_req_size -128;
			}
			for (i = 0; i < bc; i++) {
				event->tbuf[bp++] = event->dma0_req_data[i];
				//printf("data is 0x%2x,  i is %d  \n", event->dma0_req_data[i], i);
				//printf("data is 0x%2x,  bp is %d \n", event->tbuf[bp-1], bp-1);
			}
		}
		if (event->dma0_req_type == DMA_DTYPE_WR_REQ_MORE)  {
			if (event->dma0_wr_partial <= 128)  
				bc = event->dma0_wr_partial;
			else {
			   bc = 128;
			   //event->dma0_wr_partial -= 128;
			}
			for (i = 0; i < bc; i++) {
				event->tbuf[bp++] = event->dma0_req_data[i];
				//printf("data is 0x%2x,  i is %d  \n", event->dma0_req_data[i], i);
				//printf("data is 0x%2x,  bp is %d \n", event->tbuf[bp-1], bp-1);
			}
		}
		if (event->dma0_req_type == DMA_DTYPE_ATOMIC)  {
		// for Atomic memory ops, data xfer is always 16B; dsize refers to size of operand (4B or 8B)
		// Atomic memory ops also have one more char to send on socket
		// atomic_le will be ORed into bit 7 (msb) of dma0_atomic_op if set, LE order for atomic ops
			event->tbuf[bp++] = (event->dma0_atomic_op ) & 0x3F;
			if (event->dma0_atomic_le == 1)
				event->tbuf[bp-1] |= 0x80;
			//printf("event->tbuf[8] is 0x%2x \n", event->tbuf[bp-1]);
			for (i = 0; i < 16; i++) {
				event->tbuf[bp++] = event->dma0_req_data[i];
			//	printf("data is 0x%2x,  i is %d  \n", event->dma0_req_data[i], i);
			//	printf("data is 0x%2x,  bp is %d \n", event->tbuf[bp-1], bp-1);
			}
		}
		//printf("PSL_SIGNAL_PSL_MODEL: event->dma0_dvalid =1 send to PSL, tbuf[0] is 0x%02x  bp is %2d \n", event->tbuf[0], bp);
		event->dma0_dvalid = 0;
	}
#endif

	if (event->aux2_change) {
		event->tbuf[0] = event->tbuf[0] | 0x08;
		event->tbuf[bp++] =
		    (((event->buffer_read_latency) << 4) & 0xF0) |
		    (((event->job_running)
		      << 1) & 0x2) | (event->job_done & 1);
		for (i = 0; i < 8; i++) {
			event->tbuf[bp++] =
			    ((event->job_error) >> ((7 - i) * 8)) & 0xFF;
		}
		event->tbuf[bp++] = (((event->job_cack_llcmd) << 3) & 0x08) |
		    (((event->job_yield) << 2) & 0x04) |
		    (((event->timebase_request) << 1) & 0x03) |
		    ((event->parity_enable) & 0x01);
		event->aux2_change = 0;
	}
	if (event->mmio_ack) {
		event->tbuf[0] = event->tbuf[0] | 0x04;
		for (i = 0; i < 8; i++) {
			event->tbuf[bp++] =
			    ((event->mmio_rdata) >> ((7 - i) * 8)) & 0xFF;
		}
//printf("PSL_SIGNAL_PSL_MODEL: event->mmio_ack =1 send to PSL, tbuf[0] is 0x%02x  bp is %2d \n", event->tbuf[0], bp);
		event->tbuf[bp++] = event->mmio_rdata_parity;
		event->mmio_ack = 0;
	}
	if (event->buffer_rdata_valid) {
		event->tbuf[0] = event->tbuf[0] | 0x02;
		for (i = 0; i < 128; i++) {
			event->tbuf[bp++] = event->buffer_rdata[i];
		}
		for (i = 0; i < 2; i++) {
			event->tbuf[bp++] = event->buffer_rparity[i];
		}
		event->buffer_rdata_valid = 0;
	}
	if (event->command_valid) {
		event->tbuf[0] = event->tbuf[0] | 0x01;
		event->tbuf[bp++] = event->command_tag;
		event->tbuf[bp++] = (((event->command_abort) << 5) & 0xE0) |
		    (((event->command_code) >> 8) & 0x1F);
		event->tbuf[bp++] = event->command_code & 0xFF;
		event->tbuf[bp++] =
		    (((event->command_tag_parity) << 6) & 0x40) |
		    (((event->command_code_parity)
		      << 5) & 0x20) | (((event->command_address_parity) << 4) &
				       0x10) | (((event->command_size)
						 >> 8) & 0x0F);
		event->tbuf[bp++] = event->command_size & 0xFF;
		for (i = 0; i < 8; i++) {
			event->tbuf[bp++] =
			    ((event->command_address) >> ((7 - i) * 8)) & 0xFF;
		}
		for (i = 0; i < 2; i++) {
			event->tbuf[bp++] =
			    ((event->command_handle) >> ((1 - i) * 8)) & 0xFF;
		}
#if defined PSL9 || PSL9lite
		event->tbuf[bp++] = event->command_cpagesize;
#endif
		//printf("PSL_SIGNAL_PSL_MODEL: event->command_valid =1 send to PSL, tbuf[0] is 0x%02x  bp is %2d \n", event->tbuf[0], bp);
		event->command_valid = 0;
	}


        // dump tbuf
//	if ( bp > 1 ) {
//	  printf( "lgt: psl_signal_psl_model: tbuf length:0x%02x tbuf: 0x", bp ); 
//	  for ( i = 0; i < bp; i++ ) printf( "%02x", event->tbuf[i] );
//	  printf( "\n" );
//	}

	bl = bp;
	bp = 0;
	while (bp < bl) {
		bc = send(event->sockfd, event->tbuf + bp, bl - bp, 0);
		if (bc < 0) {
			return PSL_TRANSMISSION_ERROR; }
		bp += bc;
	}
	return PSL_SUCCESS;
}

/* This function checks the socket connection for data from the external AFU
 * simulator. It needs to be called periodically to poll the socket connection.
 * It will update the AFU_EVENT structure.
 * It returns a 1 if there are new events to process, 0 if not, -1 on error or
 * close.  On a 1 return, the following functions should be called to retrieve
 * the individual event:
 * psl_get_command
 * psl_get_buffer_read_data
 * psl_get_mmio_acknowledge
 * A psl command can come at any time so that function should always be called
 * but buffer read data and MMIO acknowledges will only come as a result of
 * actions from the PSL simulation so if it is known that there are no
 * outstanding actions, these need not be called. The check in these functions
 * is very quick though so it also probably wouldn't hurt to always call them */

int psl_get_afu_events(struct AFU_EVENT *event)
{
	int bc = 0;
	uint32_t rbc = 1;
#ifdef PSL9
	uint32_t pbc = 0;
#endif
	fd_set watchset;	/* fds to read from */
	/* initialize watchset */
	FD_ZERO(&watchset);
	FD_SET(event->sockfd, &watchset);
	select(event->sockfd + 1, &watchset, NULL, NULL, NULL);
	if (event->rbp == 0) {
		if ((bc = recv(event->sockfd, event->rbuf, 1, 0)) == -1) {
			if (errno == EWOULDBLOCK) {
				return 0;
			} else {
				return -1;
			}
		}
		event->rbp += bc;
	}
	if (bc == 0)
		return -1;
	if (event->rbp != 0) {
		if ((event->rbuf[0] & 0x10) != 0) {
			event->clock = 0;
			if (event->rbuf[0] == 0x10) {
				event->rbp = 0;
				return 1;
			}
		}
//printf("PSL_GET_AFU_EVENT-1 - rbuf[0] is 0x%02x and e->rbp = %2d  \n", event->rbuf[0], event->rbp);
			if ((event->rbuf[0] & 0x08) != 0)
				rbc += 10;
			if ((event->rbuf[0] & 0x04) != 0)
				rbc += 9;
		 	if ((event->rbuf[0] & 0x02) != 0)
				rbc += 130;
			if ((event->rbuf[0] & 0x01) != 0)
#if defined PSL9 || PSL9lite
			// add one byte for cpagesize
				rbc += 16;
#else
				rbc += 15;
#endif 

#ifdef PSL9
//printf("PSL_GET_AFU_EVENT-2 - rbuf[0] is 0x%02x and rbc is %2d \n", event->rbuf[0], rbc);
			if ((event->rbuf[0] & 0x80) != 0)  {
				rbc += 7;
		// this only gets us a dma rd op w/o data, have to add more to rbc so need to see what dtype  & req_size are)
				if ((bc = recv(event->sockfd, event->rbuf + event->rbp, 3, 0)) == -1) {
					if (errno == EWOULDBLOCK) {
						return 0;
					} else {
						return -1;
						}
				}
				event->rbp += bc;
		// event->dma0_req_size has size of TOTAL DMA data xfer
				event->dma0_req_size = event->rbuf[2];
				//printf("event->rbuf[2] is 0x%2x  \n", event->rbuf[2]);
				event->dma0_req_size = (event->dma0_req_size << 8) | event->rbuf[3];
				//printf("event->dma0_req_size is 0x%3x \n", event->dma0_req_size);
				if ((event->rbuf[1] & 0x07) == DMA_DTYPE_WR_REQ_128) {
 					if (event->dma0_req_size <= 128) {
					rbc += event->dma0_req_size;
					pbc = event->dma0_req_size;
					event->dma0_wr_partial = 0;
				} else  {
					rbc += 128;
					pbc = 128;
					event->dma0_wr_partial = event->dma0_req_size - 128;;
					// initalize  event->dma0_wr_partial to show remaining bytes
					}
				}
				if ((event->rbuf[1] & 0x07) == DMA_DTYPE_WR_REQ_MORE) {
 					if (event->dma0_wr_partial <= 128) { //TODO testing
					rbc += event->dma0_wr_partial;
					pbc = event->dma0_wr_partial;
					event->dma0_wr_partial = 0;
				} else  {
					rbc += 128;
					pbc = 128;
					event->dma0_wr_partial -= 128;
					// decrement event->dma0_wr_partial here
					}
				}
				

		// If this is an Atomic Memory Op, will have one extra char for atomic_op and 16 for data payload
				if ((event->rbuf[1] & 0x07) == DMA_DTYPE_ATOMIC) 
					rbc += 17;
			}
#endif
	}
	if ((bc =
	     recv(event->sockfd, event->rbuf + event->rbp, rbc - event->rbp,
		  0)) == -1) {
		if (errno == EWOULDBLOCK) {
			return 0;
		} else {
			return -1;
		}
	}
	if (bc == 0)
		return -1;
	event->rbp += bc;
	if (event->rbp < rbc)
		return 0;

	// dump rbuf
//	printf( "lgt: psl_get_afu_events: rbuf length:0x%02x rbuf: 0x", rbc ); 
//	int i = 0;
//	for ( i = 0; i < rbc; i++ ) printf( "%02x", event->rbuf[i] );
//	printf( "\n" ); 

	rbc = 1;
#ifdef PSL9
	if ((event->rbuf[0] & 0x80) != 0) {
		event->dma0_dvalid = 1;
//printf("event->dma0_dvalid is 1  and rbc is 0x%2x \n", rbc);
		event->dma0_req_type = (event->rbuf[rbc] & 0x7);
		//printf("event->rbuf[0] is 0x%2x type is 0x%2x \n", event->rbuf[rbc-1], event->dma0_req_type);
		//printf("event->rbuf[%x] is 0x%2x  \n", rbc, event->rbuf[rbc]);
		rbc +=1;
		event->dma0_req_size = event->rbuf[rbc++];
		//printf("event->rbuf[%x] is 0x%2x  \n", rbc-1, event->rbuf[rbc-1]);
		event->dma0_req_size = (event->dma0_req_size << 8) | event->rbuf[rbc++];
		//printf("event->dma0_req_size is 0x%3x \n", event->dma0_req_size);
		//printf("event->rbuf[%x] is 0x%2x  \n", rbc-1, event->rbuf[rbc-1]);
		event->dma0_req_utag = event->rbuf[rbc++];
		//printf("event->rbuf[%x] is 0x%2x  \n", rbc-1, event->rbuf[rbc-1]);
		event->dma0_req_utag = (event->dma0_req_utag << 8) | event->rbuf[rbc++];
		//printf("event->dma0_req_utag is 0x%3x \n", event->dma0_req_utag);
		//printf("event->rbuf[%x] is 0x%2x  \n", rbc-1, event->rbuf[rbc-1]);
		event->dma0_req_itag = event->rbuf[rbc++];
		//printf("event->rbuf[%x] is 0x%2x  \n", rbc-1, event->rbuf[rbc-1]);
		event->dma0_req_itag = (event->dma0_req_itag << 8) | event->rbuf[rbc++];
		//printf("event->dma0_req_itag is 0x%3x \n", event->dma0_req_itag);
		//printf("event->rbuf[%x] is 0x%2x  \n", rbc-1, event->rbuf[rbc-1]);
		//printf("event->rbuf[%x] is 0x%2x  \n", rbc, event->rbuf[rbc]);
		//printf("event->dma0_req_size is 0x%3x \n", event->dma0_req_size);
		// if type is 1 (dma read req), no data to xfer here 
		//if (event->dma0_req_type == DMA_DTYPE_WR_REQ_128)  { 
		// for DMA writes that are greater than 128B total, AFU MUST send max 128B per socket event
		//	for (bc = 0; bc < event->dma0_req_size; bc++) {
		//		event->dma0_req_data[bc] = event->rbuf[rbc++];
			//printf("data is 0x%2x, bc is %d, rbc is %d \n", event->rbuf[rbc-1], bc, rbc-1);
		//	}
		//}
		if ((event->dma0_req_type == DMA_DTYPE_WR_REQ_MORE) || (event->dma0_req_type == DMA_DTYPE_WR_REQ_128))  { 
			for (bc = 0; bc < pbc; bc++) {
				event->dma0_req_data[bc] = event->rbuf[rbc++];
			//printf("data is 0x%2x, bc is %d, rbc is %d \n", event->rbuf[rbc-1], bc, rbc-1);
			}
	
		}
		if (event->dma0_req_type == DMA_DTYPE_ATOMIC)  {
		// for Atomic memory ops, data xfer is always 16B; dsize refers to size of operand (4B or 8B)
		// Atomic memory ops also have one more char to send on socket
		// if bit 7 (msb) of atomic_op ==1 then atomic_le gets set to 1, but we leave bit in atomic_op as it
		// next gets transferred to libcxl for AMO emulation
			event->dma0_atomic_op = event->rbuf[rbc++];
			if ((event->dma0_atomic_op & 0x80) == 1) 
				event->dma0_atomic_le = 1;
			else
				event->dma0_atomic_le = 0;
			//printf("event->dma0_atomic_op is 0x%3x \n", event->dma0_atomic_op);
			for (bc = 0; bc < 16; bc++) {
				event->dma0_req_data[bc] = event->rbuf[rbc++];
			//printf("data is 0x%2x, bc is %d, rbc is %d \n", event->rbuf[rbc-1], bc, rbc-1);
			//	printf("data is 0x%2x,  rbc is %d  \n", event->dma0_req_data[rbc], rbc);
			}
		}

	} else {
		event->dma0_dvalid = 0;

	}
#endif

	if ((event->rbuf[0] & 0x08) != 0) {
		event->aux2_change = 1;
		event->buffer_read_latency = (event->rbuf[rbc]) >> 4;
		event->job_running = ((event->rbuf[rbc]) >> 1) & 0x01;
		event->job_done = (event->rbuf[rbc++]) & 0x01;
		event->job_error = 0;
		for (bc = 0; bc < 8; bc++) {
			event->job_error =
			    ((event->job_error) << 8) | event->rbuf[rbc++];
		}
		event->job_cack_llcmd = ((event->rbuf[rbc]) >> 3) & 0x01;
		event->job_yield = ((event->rbuf[rbc]) >> 2) & 0x01;
		event->timebase_request = ((event->rbuf[rbc]) >> 1) & 0x01;
		event->parity_enable = (event->rbuf[rbc++]) & 0x01;
	} else {
		event->aux2_change = 0;
	}
	if ((event->rbuf[0] & 0x04) != 0) {
		event->mmio_ack = 1;
		event->mmio_rdata = 0;
		for (bc = 0; bc < 8; bc++) {
			event->mmio_rdata =
			    ((event->mmio_rdata) << 8) | event->rbuf[rbc++];
		}
		event->mmio_rdata_parity = event->rbuf[rbc++];
//printf(" rbc is %d \n",rbc);
	} else {
		event->mmio_ack = 0;
	}
	if ((event->rbuf[0] & 0x02) != 0) {
		event->buffer_rdata_valid = 1;
		for (bc = 0; bc < 128; bc++) {
			event->buffer_rdata[bc] = event->rbuf[rbc++];
		}
		for (bc = 0; bc < 2; bc++) {
			event->buffer_rparity[bc] = event->rbuf[rbc++];
		}
	} else {
		event->buffer_rdata_valid = 0;
	}
	if ((event->rbuf[0] & 0x01) != 0)  {
	  //printf("received a cmd, rbuf[0] is 0x%2x \n", event->rbuf[0]);
		event->command_valid = 1;
		event->command_tag = event->rbuf[rbc++];
		event->command_abort = (event->rbuf[rbc] >> 5) & 0x7;
		event->command_code = (event->rbuf[rbc++] & 0x1F) << 8;
		event->command_code = event->command_code | event->rbuf[rbc++];
		event->command_tag_parity = (event->rbuf[rbc] >> 6) & 0x01;
		event->command_code_parity = (event->rbuf[rbc] >> 5) & 0x01;
		event->command_address_parity = (event->rbuf[rbc] >> 4) & 0x01;
		event->command_size = (event->rbuf[rbc++] & 0x0F) << 8;
		event->command_size = event->command_size | event->rbuf[rbc++];
		event->command_address = 0;
		for (bc = 0; bc < 8; bc++) {
			event->command_address =
			    ((event->command_address) << 8) |
			    event->rbuf[rbc++];
		}
		event->command_handle = 0;
		for (bc = 0; bc < 2; bc++) {
			event->command_handle =
			    ((event->command_handle) << 8) | event->rbuf[rbc++];
		}
#if defined PSL9 || defined PSL9lite
		event->command_cpagesize = event->rbuf[rbc];
#endif
		//printf(" rbc is %2d \n",rbc);
	} else {
		event->command_valid = 0;
	}

	event->rbp = 0;
	return 1;
}

/* This function checks the socket connection for data from the external PSL
 * simulator. It needs to be called periodically to poll the socket connection.
 * (every clock cycle)  It will update the AFU_EVENT structure and returns a 1
 * if there are new events to process. */

int psl_get_psl_events(struct AFU_EVENT *event)
{
        int bc, bytes_to_read;
	uint32_t rbc = 1;
	if (event->rbp == 0) {
		if ((bc = recv(event->sockfd, event->rbuf, 1, 0)) == -1) {
			if (errno == EWOULDBLOCK) {
				return 0;
			} else {
				return -1;
			}
		}
		if (bc == 0)
			return -1;
		event->rbp += bc;
	}
	if (event->rbp != 0) {
		if ((event->rbuf[0] & 0x40) != 0) {
			event->clock = 1;
			psl_signal_psl_model(event);
			if (event->rbuf[0] == 0x40) {
				event->rbp = 0;
				return 1;
			}
		}
		if ((event->rbuf[0] & 0x20) != 0)
			rbc += 1;
		if ((event->rbuf[0] & 0x10) != 0)
			rbc += 10;
		if ((event->rbuf[0] & 0x08) != 0)
			rbc += 12;
		if ((event->rbuf[0] & 0x04) != 0)
#ifdef PSL9  /* need three extra bytes in response for xlat response returns and pagesize */
			rbc += 9;
#else
			rbc += 6;
#endif /* #ifdef PSL9 */
		if ((event->rbuf[0] & 0x02) != 0)
			rbc += 3;
		if ((event->rbuf[0] & 0x01) != 0)
			rbc += 133;
#ifdef PSL9
		// have to look at second byte if this is a dma op
		if ((event->rbuf[0] & 0x80) != 0) {
			if ((bc = recv(event->sockfd, event->rbuf + event->rbp, 1, 0)) == -1) {
				if (errno == EWOULDBLOCK) {
					return 0;
				} else {
					return -1;
				}
			}
			if (bc == 0)
				return -1;
			event->rbp += bc;
			// sent_utag_status bc is 3, dma read cpl can be up to 139
			if ((event->rbuf[1] & 0xC0) != 0)
				rbc += 3;  
			//printf("PSL_GET_PSL_EVENTS and event->rbuf[1] is 0x%x and rbc= 0x%x \n", event->rbuf[1], rbc);
			// have to look at third & fourth byte if this is completion data
			if ((event->rbuf[1] & 0x30) != 0)  {
				if ((bc = recv(event->sockfd, event->rbuf + event->rbp, 1, 0)) == -1) {
					if (errno == EWOULDBLOCK) {
						return 0;
					} else {
						return -1;
					}
				}
				if (bc == 0)
					return -1;
				event->rbp += bc;
				// look at next byte to get rest of cpl_size and type 
				if ((bc = recv(event->sockfd, event->rbuf + event->rbp, 1, 0)) == -1) {
					if (errno == EWOULDBLOCK) {
						return 0;
					} else {
						return -1;
					}
				}
				if (bc == 0)
					return -1;
				event->rbp += bc;
				bytes_to_read = (event->rbuf[1] & 0x0F) << 8;
				bytes_to_read = ( bytes_to_read | event->rbuf[2] );
				if (bytes_to_read > 128)  { // need to look at next byte to see type 
					if (((event->rbuf[3] & 0xF0) >> 4) == 0)
						rbc = rbc + 7 + 128;
					if (((event->rbuf[3] & 0xF0) >> 4) == 1)
						rbc = rbc + 7 + (bytes_to_read - 128);
				} else  
				// this will be ok for single cycle cpl bc, have to also add 7  
				rbc = rbc + 7 + bytes_to_read;
	
				//printf("rbc will be 0x%2x and event->rbp is 0x%2X \n", rbc, event->rbp);
			}

		}	
#endif /* ifdef PSL9 */
		if ((bc =
		     recv(event->sockfd, event->rbuf + event->rbp,
			  rbc - event->rbp, 0)) == -1) {
			if (errno == EWOULDBLOCK) {
				return 0;
			} else {
				return -1;
			}
		}
		if (bc == 0)
			return -1;
		event->rbp += bc;
	}
	if (event->rbp < rbc)
		return 0;
	
	// dump rbuf
//	printf( "lgt: psl_get_psl_events: rbuf length:0x%02x rbuf: 0x", rbc ); 
//	int i;
//	for ( i = 0; i < rbc; i++ ) printf( "%02x", event->rbuf[i] );
//	printf( "\n" ); 

	rbc = 1;
#ifdef PSL9
//printf("PSL_GET_PSL_EVENTS event->rbuf[0] is 0x%2x and event->rbuf[1] is 0x%2x \n", event->rbuf[0], event->rbuf[1]);
	if (((event->rbuf[0] & 0x80) == 0x80) && ((event->rbuf[1] & 0x30) == 0x30)) {
		event->dma0_completion_valid = 1;
//printf("PSL_GET_PSL_EVENTS setting event->dma0_completion_valid to 1 \n");
		event->dma0_completion_size = event->rbuf[rbc++];
		event->dma0_completion_size = ( ( event->dma0_completion_size & 0xF ) << 8 ) | event->rbuf[rbc++];
		event->dma0_completion_type = ((event->rbuf[rbc] >> 4 ) & 0x07);
		event->dma0_completion_utag = event->rbuf[rbc++];
		event->dma0_completion_utag =
			((event->dma0_completion_utag & 0x03) << 8 ) | event->rbuf[rbc++];
		event->dma0_completion_laddr = event->rbuf[rbc++];
		event->dma0_completion_byte_count = event->rbuf[rbc++];
		bytes_to_read = event->rbuf[rbc++];
		//printf("event->rbuf = 0x%3x \n", bytes_to_read);
		event->dma0_completion_laddr = (( (bytes_to_read & 0x0f0) <<4) | event->dma0_completion_laddr );
		//event->dma0_completion_laddr = ((event->rbuf[rbc++] << 4) | event->dma0_completion_laddr);
		event->dma0_completion_byte_count = (( (bytes_to_read & 0x0f) <<8) | event->dma0_completion_byte_count );
		//event->dma0_completion_byte_count = ((event->rbuf[rbc] << 8) | event->dma0_completion_byte_count);
		//printf("event->dma0_completion_size = 0x%3x \n", event->dma0_completion_size);
		//printf("event->dma0_completion_type = 0x%3x \n", event->dma0_completion_type);
		//printf("event->dma0_completion_utag = 0x%3x \n", event->dma0_completion_utag);
		//printf("event->dma0_completion_laddr = 0x%3x \n", event->dma0_completion_laddr);
		//printf("event->dma0_completion_byte_count = 0x%3x \n", event->dma0_completion_byte_count);
		if (event->dma0_completion_size > 128) {
			if (event->dma0_completion_type == 0)
				bytes_to_read = 128;
			if (event->dma0_completion_type == 1)
				bytes_to_read = event->dma0_completion_size - 128;
		}  else // cpl_byte_count < = 128 so just single cycle
			bytes_to_read = event->dma0_completion_size;
		//printf("bytes to read (after adustment) = 0x%3x \n", bytes_to_read);
		//printf("data is 0x");
		for (bc = 0; bc < bytes_to_read; bc++) {
			event->dma0_completion_data[bc] = event->rbuf[rbc++];
			//printf("%02x", event->dma0_completion_data[bc]);
		}
		//printf("/n");
	}else {
		event->dma0_completion_valid = 0;
	}
	if (((event->rbuf[0] & 0x80) == 0x80) && ((event->rbuf[1] & 0xC0) == 0xC0)) {
		event->dma0_sent_utag_valid = 1;
		//printf("PSL_GET_PSL _EVENTS setting event->dma0_sent_utag_valid to 1 \n");
		event->dma0_sent_utag_status = (event->rbuf[rbc++]  & 0x03);
		event->dma0_sent_utag = event->rbuf[rbc++];
		event->dma0_sent_utag =
			((event->dma0_sent_utag & 0x03) << 8 ) | event->rbuf[rbc++];
		//printf("dma0_sent_utag_status is 0x%3x \n", event->dma0_sent_utag_status);
		//printf("event->rbuf[1] is 0x%3x  \n", event->rbuf[1]);
		//printf("event->rbuf[2] is 0x%3x  \n", event->rbuf[2]);
		//printf("event->rbuf[%x] is 0x%3x  \n", rbc-1, event->rbuf[rbc-1]);
		//printf("dma0_sent_utag is 0x%3x \n", event->dma0_sent_utag);
	}else {
		event->dma0_sent_utag_status = 0;
	}
#endif 

	if (event->rbuf[0] & 0x20) {
		event->aux1_change = 1;
		event->room = event->rbuf[rbc++];
	} else {
		event->aux1_change = 0;
	}
	if (event->rbuf[0] & 0x10) {
		event->job_valid = 1;
		event->job_code = event->rbuf[rbc++];
		event->job_address = 0;
		for (bc = 0; bc < 8; bc++) {
			event->job_address =
			    ((event->job_address) << 8) | event->rbuf[rbc++];
		}
		event->job_address_parity = (event->rbuf[rbc] >> 1) & 0x01;
		event->job_code_parity = event->rbuf[rbc++] & 0x01;
	} else {
		event->job_valid = 0;
	}
	if (event->rbuf[0] & 0x08) {
		event->mmio_valid = 1;
		event->mmio_wdata_parity = ((event->rbuf[rbc]) >> 4) & 1;
		event->mmio_address_parity = ((event->rbuf[rbc]) >> 3) & 1;
		event->mmio_afudescaccess = ((event->rbuf[rbc]) >> 2) & 1;
		event->mmio_double = ((event->rbuf[rbc]) >> 1) & 1;
		event->mmio_read = (event->rbuf[rbc++]) & 1;
		event->mmio_address = 0;
		for (bc = 0; bc < 3; bc++) {
			event->mmio_address =
			    ((event->mmio_address) << 8) | event->rbuf[rbc++];
		}
		event->mmio_wdata = 0;
		for (bc = 0; bc < 8; bc++) {
			event->mmio_wdata =
			    ((event->mmio_wdata) << 8) | event->rbuf[rbc++];
		}
	} else {
		event->mmio_valid = 0;
	}
	if (event->rbuf[0] & 0x04) {
		event->response_valid = 1;
		event->response_tag = event->rbuf[rbc++];
		event->response_tag_parity = event->rbuf[rbc++];
		event->response_code = event->rbuf[rbc++];
		event->cache_position = event->rbuf[rbc++] << 5;
		event->cache_position =
		    event->cache_position | (((event->rbuf[rbc]) >> 3) & 0x1F);
		event->cache_state = ((event->rbuf[rbc]) >> 2) & 0x3;
		event->credits = (event->rbuf[rbc++] << 8) & 0x100;
		event->credits = event->credits | event->rbuf[rbc++];
#ifdef PSL9
		event->response_dma0_itag_parity = (((event->rbuf[rbc++]) & 0x10) >>4);
		event->response_dma0_itag = event->rbuf[rbc-1];
		event->response_dma0_itag =
		    (((event->response_dma0_itag) & 0x1) << 8) | event->rbuf[rbc++];
		event->response_r_pgsize = event->rbuf[rbc++];
//		printf( "lgt: psl_get_psl_events: respsonse tag=0x%02x, tag parity=0x%02x, respsonse code=0x%02x. respsonse itag=0x%02x, \n", event->response_tag, event->response_tag_parity, event->response_code, event->response_dma0_itag );
#endif


	} else {
		event->response_valid = 0;
	}
	if (event->rbuf[0] & 0x02) {
		event->buffer_read = 1;
		event->buffer_read_tag = event->rbuf[rbc++];
		event->buffer_read_tag_parity = event->rbuf[rbc++];
		if ((event->rbuf[rbc]) >> 7) {
			event->buffer_read_length = 128;
		} else {
			event->buffer_read_length = 64;
		}
		event->buffer_read_address = (event->rbuf[rbc++]) & 0x3F;
	      //  printf( "lgt: psl_get_psl_events: buffer read: tag: 0x%02x, tag parity: 0x%02x\n", 
		 //  	event->buffer_read_tag, 
	//		event->buffer_read_tag_parity);
	} else {
		event->buffer_read = 0;
	}
	if (event->rbuf[0] & 0x01) {
		event->buffer_write = 1;
		event->buffer_write_tag = event->rbuf[rbc++];
		event->buffer_write_tag_parity = event->rbuf[rbc++];
		if ((event->rbuf[rbc]) >> 7) {
			event->buffer_write_length = 128;
		} else {
			event->buffer_write_length = 64;
		}
		event->buffer_write_address = (event->rbuf[rbc++]) & 0x3F;
		for (bc = 0; bc < 128; bc++) {
			event->buffer_wdata[bc] = event->rbuf[rbc++];
		}
		for (bc = 0; bc < 2; bc++) {
			event->buffer_wparity[bc] = event->rbuf[rbc++];
		}
	//        printf( "lgt: psl_get_psl_events: buffer write: tag: 0x%02x, tag parity: 0x%02x\n", 
	//	   	event->buffer_write_tag, 
	//		event->buffer_write_tag_parity);
	} else {
		event->buffer_write = 0;
	}
	event->rbp = 0;
	return 1;
}

/* Call this on the AFU side to build a command to send to PSL */

int
psl_afu_command(struct AFU_EVENT *event,
		uint32_t tag,
		uint32_t tag_parity,
		uint32_t code,
		uint32_t code_parity,
		uint64_t address,
		uint64_t address_parity,
#if defined PSL9 || defined PSL9lite
		uint32_t size, uint32_t abort, uint32_t handle, uint32_t cpagesize)
#else
		uint32_t size, uint32_t abort, uint32_t handle)
#endif
{
	if (event->command_valid) {
		return PSL_DOUBLE_COMMAND;
	} else {
		event->command_valid = 1;
		event->command_tag = tag;
		event->command_tag_parity = tag_parity;
		event->command_code = code;
		event->command_code_parity = code_parity;
		event->command_address = address;
		event->command_address_parity = address_parity;
		event->command_size = size;
		event->command_abort = abort;
		event->command_handle = handle;
#if defined PSL9 || defined PSL9lite
		event->command_cpagesize = cpagesize;
#endif
#ifdef PSL9
// if cmd is for xlat_abrt_rd or xlat_abrt_wr, increment counters here
// instead of sent_utag_sts bc there won't be a sent utag sts for aborts
		if (code == PSL_COMMAND_ITAG_ABRT_RD)
			event->dma0_rd_credits +=1;
		if (code == PSL_COMMAND_ITAG_ABRT_WR)
			event->dma0_wr_credits +=1;
#endif			
		return PSL_SUCCESS;
	}
}

/* Call this on the AFU side to build an MMIO acknowledge. Read data is used
 * only for MMIO reads, ignored otherwise */

int
psl_afu_mmio_ack(struct AFU_EVENT *event,
		 uint64_t read_data, uint32_t read_data_parity)
{
	if (event->mmio_ack) {
		return PSL_DOUBLE_COMMAND;
	} else {
		event->mmio_ack = 1;
		event->mmio_rdata = read_data;
		event->mmio_rdata_parity = read_data_parity;
		return PSL_SUCCESS;
	}
}

/* Call this on the AFU side to build buffer read data. Length should be
 * 64 or 128 */

int
psl_afu_read_buffer_data(struct AFU_EVENT *event,
			 uint32_t length,
			 uint8_t * read_data, uint8_t * read_parity)
{
	if (event->buffer_rdata_valid) {
		return PSL_DOUBLE_COMMAND;
	} else {
		event->buffer_rdata_valid = 1;
		memcpy(event->buffer_rdata, read_data, length);
		event->buffer_read_length = length;
		memcpy(event->buffer_rparity, read_parity, length / 64);
		return PSL_SUCCESS;
	}
}

/* Call this on the AFU side to change the auxilliary signals
 * (running, done, job error, buffer read latency) */

int
psl_afu_aux2_change(struct AFU_EVENT *event,
		    uint32_t running,
		    uint32_t done,
		    uint32_t cack_llcmd,
		    uint64_t job_error,
		    uint32_t yield,
		    uint32_t tb_request,
		    uint32_t par_enable, uint32_t read_latency)
{
	if (event->aux2_change) {
		return PSL_DOUBLE_COMMAND;
	} else {
		event->aux2_change = 1;
		event->job_running = running;
		event->job_done = done;
		event->job_cack_llcmd = cack_llcmd;
		event->job_error = job_error;
		event->job_yield = yield;
		event->timebase_request = tb_request;
		event->parity_enable = par_enable;
		event->buffer_read_latency = read_latency;
		return PSL_SUCCESS;
	}
}

#ifdef PSL9
/* Call this on the AFU side to send a DMA0 req */

int
psl_afu_dma0_req(struct AFU_EVENT *event,
		uint32_t utag,
		uint32_t itag,
		uint32_t type,
		uint32_t size,
		uint32_t atomic_op,
		uint32_t atomic_le,
		uint8_t * dma_wr_data )

{
	//check to be sure rd & wr credits are available, otherwise reject
	//if ((event->dma0_req_type == DMA_DTYPE_RD_REQ) && (event->dma0_rd_credits <= 0))  {
	//	printf("AFU IS OUT OF DMA RD CREDITS !!!!!! \n"); 
	//	return PSL_NO_DMA_PORT_CREDITS; }
	//if ((event->dma0_req_type != DMA_DTYPE_RD_REQ) && (event->dma0_wr_credits == 0)) {
	//	printf("AFU IS OUT OF DMA WR CREDITS !!!!!! \n"); 
	//	return PSL_NO_DMA_PORT_CREDITS; }
	if  (event->dma0_dvalid) {
		printf("ALREADY A DMA CMD PENDING  !!!!!! \n");
		return PSL_DOUBLE_DMA0_REQ;
	} else {
		event->dma0_req_utag = utag;
		event->dma0_req_itag = itag;
		event->dma0_req_type = type;			
		if (size > 512)
			printf("MAX DMA PAYLOAD OF 512B EXCEEDED!!! \n");
		event->dma0_req_size = size;			
		event->dma0_atomic_op = atomic_op;
		event->dma0_atomic_le = atomic_le;
		if (event->dma0_req_type == DMA_DTYPE_WR_REQ_128) { 
			event->dma0_req_size = size;
			if (size <= 128)  {
				memcpy(event->dma0_req_data, dma_wr_data, size);
				event->dma0_wr_credits--;
			} else { //the start of a >128B write operation
				event->dma0_wr_partial = size - 128;
				memcpy(event->dma0_req_data, dma_wr_data, 128);
			}
		//	event->dma0_wr_credits--;
		}
 		if (event->dma0_req_type == DMA_DTYPE_WR_REQ_MORE)  { 
			if (event->dma0_wr_partial <= 128) {
				memcpy(event->dma0_req_data, dma_wr_data, event->dma0_wr_partial);
				event->dma0_wr_credits--;
			} else {
				memcpy(event->dma0_req_data, dma_wr_data, 128);
				event->dma0_wr_partial -= 128;
			}
		}
		//	event->dma0_wr_credits--;
		if (event->dma0_req_type == DMA_DTYPE_ATOMIC)  {  
			memcpy(event->dma0_req_data, dma_wr_data, 16);
			event->dma0_wr_credits--;
		}
		if (event->dma0_req_type == DMA_DTYPE_RD_REQ)
			event->dma0_rd_credits--;
		//printf("psl_afu_dma0_req: rd_credit count is %d  wr_credit count is %d \n", event->dma0_rd_credits, event->dma0_wr_credits);
		event->dma0_dvalid = 1;			
		return PSL_SUCCESS;

	}
}

/* AFU calls this to read dma port completion bus, dma_rd_data can be up to 128B  
 * for DMA reads, or 4B or 8B for AMO returns, there is NO_parity. */

int
afu_get_dma0_cpl_bus_data(struct AFU_EVENT *event,
		 uint32_t utag,
		 uint32_t cpl_type,
		 uint32_t cpl_size, 
		 uint32_t laddr,
		 uint32_t byte_count, uint8_t * dma_rd_data)
{
// if AFU has already checked/reset event->dma0_completion_valid, this has to change
	if (!event->dma0_completion_valid) {
	        // printf("THERE ISN'T ANY VALID BUFFER READ DATA- dma0_completion_valid != 1 \n");
		return PSL_BUFFER_READ_DATA_NOT_VALID;
	} else { 
		//printf("VALID CPL DATA TO READ \n");
		event->dma0_completion_valid = 0;
		utag = event->dma0_completion_utag;
		cpl_type = event->dma0_completion_type;
		cpl_size = event->dma0_completion_size;
		laddr = event->dma0_completion_laddr;
		byte_count = event->dma0_completion_byte_count;
		// is this a multi cycle transaction? 
		if (byte_count > 128)  {
			if (cpl_type == 0)
				memcpy(dma_rd_data, event->dma0_completion_data, 128);
			if (cpl_type == 1)
			  //memcpy(&(dma_rd_data[128]), event->dma0_completion_data, cpl_size - 128);
			  memcpy( dma_rd_data, event->dma0_completion_data, cpl_size - 128 );
		} else  // cpl_byte_count <= 128 so just single cycle
				memcpy(dma_rd_data, event->dma0_completion_data, cpl_size);
		return PSL_SUCCESS;
	}
}

/* AFU calls this to read a dma port sent_utag_status on the DMA bus. */

int
afu_get_dma0_sent_utag(struct AFU_EVENT *event,
		 uint32_t utag,
		 uint32_t sent_sts)
{
// if AFU doesn't use this to function, AFU has to manually increment credit count
	if (!event->dma0_sent_utag_valid) {
		return PSL_BUFFER_READ_DATA_NOT_VALID;
	} else {
		utag = event->dma0_sent_utag;
		sent_sts = event->dma0_sent_utag_status;
		//printf("sent_utag_sts is 0%x \n", event->dma0_sent_utag_status);
		event->dma0_sent_utag_valid = 0;
		if (event->dma0_sent_utag_status == DMA_SENT_UTAG_STS_RD)
			event->dma0_rd_credits++;
		else if (event->dma0_sent_utag_status == DMA_SENT_UTAG_STS_WR)
			event->dma0_wr_credits++;
		else {
			printf("Transaction FAILED, can't tell which credit counter to increment so will increment both!! \n");
			//event->dma0_wr_credits++;
			//event->dma0_rd_credits++;
		     }

		//printf("afu_get_dma0_sent_utag: sent_sts is %d  rd_credit count is %d  wr_credit count is %d \n", sent_sts, event->dma0_rd_credits, event->dma0_wr_credits);
		return PSL_SUCCESS;
	}
}



#endif
