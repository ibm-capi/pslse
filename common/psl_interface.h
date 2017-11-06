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

#ifndef __psl_interface_h__
#define __psl_interface_h__ 1

#include "psl_interface_t.h"

/* Call this at startup to reset all the event indicators */

void psl_event_reset(struct AFU_EVENT *event);

/* Call this once after creation to initialize the AFU_EVENT structure and open
 * a socket conection to an AFU server.  This function initializes the PSL side
 * of the interface which is the client in the socket connection server_host
 * should be the name of the server hosting the simulation of the AFU and port
 * is the active port on that server */

int psl_init_afu_event(struct AFU_EVENT *event, char *server_host, int port);

/* Call this to close the socket connection from either side */

int psl_close_afu_event(struct AFU_EVENT *event);

/* Call this once after creation to initialize the AFU_EVENT structure.  This
 * function initializes the AFU side of the interface which is the server in
 * the socket connection */

int psl_serv_afu_event(struct AFU_EVENT *event, int port);

/* Call this to change auxilliary signals (room) */

int psl_aux1_change(struct AFU_EVENT *event, uint32_t room);

/* Call this to create an accelerator control command */

int psl_job_control(struct AFU_EVENT *event,
		    uint32_t job_code, uint64_t address);

/* Call this to create an MMIO read command. If the dbl argument is 1, 64 bits
 * are transferred.  If it is 0, 32 bits are transferred */

int psl_mmio_read(struct AFU_EVENT *event, uint32_t dbl, uint32_t address,
		  uint32_t afudescaccess);

/* Call this to create an MMIO write command. If the dbl argument is 1, 64 bits
 * are transferred.  If it is 0, 32 bits are transferred (least significant
 * 32 bits of write_data */

int psl_mmio_write(struct AFU_EVENT *event,
		   uint32_t dbl, uint32_t address, uint64_t write_data,
		   uint32_t afudescaccess);

/* Call this to create a command response */

int psl_response(struct AFU_EVENT *event,
		 uint32_t tag,
		 uint32_t response_code,
#if defined PSL9 || defined PSL9lite
//		 uint32_t response_extra, uint32_t response_r_pgsize,
		 int credits, uint32_t cache_state, uint32_t cache_position, 
		 uint32_t itag, uint32_t pagesize, uint32_t resp_extra);
#else
		 int credits, uint32_t cache_state, uint32_t cache_position);
#endif

/* Call this to read a buffer.  Length must be either 64 or 128 which is the
 * transfer size in bytes. For 64B transfers, only the first half of the array
 * is used */

int psl_buffer_read(struct AFU_EVENT *event,
		    uint32_t tag, uint64_t address, uint32_t length);

#ifdef PSL9
/* Call this to read the DMA 0 bus buffer to get the write data and DMA operation specific data. 
 * Length must be 128 which is the transfer size in bytes. DMA operation specific data is utag, itag,
 * type and size in bytes. (only size supported now is 128)   */

int psl_dma0_data_buffer_read(struct AFU_EVENT *event,
		    uint32_t tag, uint64_t address, uint32_t length);

#endif

/* Call this to write a buffer, write_data is a 32 element array of 32-bit
 * values, write_parity is a 4 element array of 32-bit values.  Length must be
 * either 64 or 128 which is the transfer size in bytes.  For 64B transfers,
 * only the first half of the array is used. */

int psl_buffer_write(struct AFU_EVENT *event,
		     uint32_t tag,
		     uint64_t address,
		     uint32_t length,
		     uint8_t * write_data, uint8_t * write_parity);

#ifdef PSL9
/* Call this to write the DMA0 read completion buffer, write_data is a 32 element array of 32-bit
 * values.  Size must be 128 at least initially, which is transfer size in bytes  */

int psl_dma0_cpl_bus_write(struct AFU_EVENT *event,
		     uint32_t utag,
		     uint32_t dsize,
		     uint32_t cpl_type,
		     uint32_t cpl_size,
	 	     uint32_t cpl_laddr,
		     uint32_t cpl_byte_count,
		     uint8_t * write_data);

/* Call this to write a dma port utag sent back on the DMA bus. */

int
psl_dma0_sent_utag(struct AFU_EVENT *event,
		 uint32_t utag,
		 uint32_t sent_sts);

int
psl_get_dma0_port(struct AFU_EVENT *event,
		uint32_t * utag,
		uint32_t * itag,
		uint32_t * type,
		uint32_t * size,
		uint32_t * atomic_op,
		uint32_t * atomic_le,
		uint8_t * dma0_req_data ); 


#endif

/* Call after an event is received from the AFU to see if previous MMIO
 * operation has been acknowledged and extract read MMIO data if available. */

int psl_get_mmio_acknowledge(struct AFU_EVENT *event, uint64_t * read_data,
			     uint32_t * read_data_parity);

/* Call after an event is received from the AFU to extract read buffer data if
 * available. read_data is a 32 element array of 32-bit values, read_parity is
 * a 4 element array of 32-bit values.
 * Note: fields in AFU_EVENT structre can also be accessed directly */

int psl_get_buffer_read_data(struct AFU_EVENT *event,
			     uint8_t * read_data, uint8_t * read_parity);

/* Call after an event is received from the AFU to extract a PSL command if
 * available.
 * Note: fields in AFU_EVENT structre can also be accessed directly */

int psl_get_command(struct AFU_EVENT *event,
		    uint32_t * command,
		    uint32_t * command_parity,
		    uint32_t * tag,
		    uint32_t * tag_parity,
		    uint64_t * address,
		    uint64_t * address_parity,
#if defined PSL9 || defined PSL9lite
		    uint32_t * size, uint32_t * abort, uint32_t * handle, uint32_t * cpagesize);
#else
		    uint32_t * size, uint32_t * abort, uint32_t * handle);
#endif

/* Call this periodically to send events and clocking synchronization to AFU */

int psl_signal_afu_model(struct AFU_EVENT *event);

/* This function checks the socket connection for data from the external AFU
 * simulator. It needs to be called periodically to poll the socket connection.
 * It will update the AFU_EVENT structure.  It returns a 1 if there are new
 * events to process, 0 if not, -1 on error or close.
 * On a 1 return, the following functions should be called to retrieve the
 * individual events.
 * psl_get_command
 * psl_get_buffer_read_data
 * psl_get_mmio_acknowledge
 * A psl command can come at any time so that function should always be called
 * but buffer read data and MMIO acknowledges will only come as a result of
 * actions from the PSL simulation so if it is known that there are no
 * outstanding actions, these need not be called. The check in these functions
 * is very quick though so it also probably wouldn't hurt to always call them */

int psl_get_afu_events(struct AFU_EVENT *event);

/* This function checks the socket connection for data from the external PSL
 * simulator. It  needs to be called periodically to poll the socket connection.
 * (every clock cycle)  It will update the AFU_EVENT structure and returns a 1
 * if there are new events to process */

int psl_get_psl_events(struct AFU_EVENT *event);

/* Call this on the AFU side to build a command to send to PSL */

int psl_afu_command(struct AFU_EVENT *event,
		    uint32_t tag,
		    uint32_t tag_parity,
		    uint32_t code,
		    uint32_t code_parity,
		    uint64_t address,
		    uint64_t address_parity,
#if defined PSL9 || defined PSL9lite
		    uint32_t size, uint32_t abort, uint32_t pad, uint32_t cpagesize);
#else
		    uint32_t size, uint32_t abort, uint32_t pad);
#endif

/* Call this on the AFU side to build an MMIO acknowledge. Read data is used
 * only for MMIO reads, ignored otherwise */

int psl_afu_mmio_ack(struct AFU_EVENT *event,
		     uint64_t read_data, uint32_t read_data_parity);

/* Call this on the AFU side to build buffer read data. Length should be
 * 64 or 128 */

int psl_afu_read_buffer_data(struct AFU_EVENT *event,
			     uint32_t length,
			     uint8_t * read_data, uint8_t * read_parity);

/* Call this on the AFU side to change the auxilliary signals
 * (running, done, job error, buffer read latency) */

int psl_afu_aux2_change(struct AFU_EVENT *event,
			uint32_t running,
			uint32_t done,
			uint32_t cack_llcmd,
			uint64_t job_error,
			uint32_t yield,
			uint32_t tb_request,
			uint32_t par_enable, uint32_t read_latency);

/* Call after an event is received from the AFU to see if any of the auxilliary
 * signals have changed values */

int psl_get_aux2_change(struct AFU_EVENT *event,
			uint32_t * job_running,
			uint32_t * job_done,
			uint32_t * job_cack_llcmd,
			uint64_t * job_error,
			uint32_t * job_yield,
			uint32_t * tb_request,
			uint32_t * par_enable, uint32_t * read_latency);

#ifdef PSL9
/* Call this on AFU side to send a DM0 request to PSL */

int psl_afu_dma0_req(struct AFU_EVENT *event,
		uint32_t utag,
		uint32_t itag,
		uint32_t type,
		uint32_t size,
		uint32_t atomic_op,
		uint32_t atomic_le,
		unsigned char dma_wr_data[128] );

int
afu_get_dma0_cpl_bus_data(struct AFU_EVENT *event,
		 uint32_t utag,
		 uint32_t cpl_type,
		 uint32_t cpl_size, 
		 uint32_t laddr,
		 uint32_t byte_count, uint8_t * dma_rd_data);

int
afu_get_dma0_sent_utag(struct AFU_EVENT *event,
		 uint32_t utag,
		 uint32_t sent_sts);


#endif /* ifdef PSL9 */

#endif
