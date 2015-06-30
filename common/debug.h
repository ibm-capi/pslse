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

#ifndef _DEBUG_H_
#define _DEBUG_H_

#include <stdint.h>
#include <stdio.h>

typedef uint8_t DBG_HEADER;

#define DBG_HEADER_VERSION		0x00
#define DBG_HEADER_PARM			0x01
#define DBG_HEADER_SOCKET_PUT           0x02
#define DBG_HEADER_SOCKET_GET           0x03
#define DBG_HEADER_AFU_CONNECT		0x04
#define DBG_HEADER_AFU_DROP   		0x05
#define DBG_HEADER_CONTEXT_ADD    	0x06
#define DBG_HEADER_CONTEXT_REMOVE 	0x07
#define DBG_HEADER_JOB_ADD       	0x08
#define DBG_HEADER_JOB_SEND       	0x09
#define DBG_HEADER_JOB_AUX2       	0x0A
#define DBG_HEADER_MMIO_MAP       	0x0B
#define DBG_HEADER_MMIO_ADD       	0x0C
#define DBG_HEADER_MMIO_SEND       	0x0D
#define DBG_HEADER_MMIO_ACK       	0x0E
#define DBG_HEADER_MMIO_RETURN       	0x0F
#define DBG_HEADER_CMD_ADD       	0x10
#define DBG_HEADER_CMD_UPDATE       	0x11
#define DBG_HEADER_CMD_CLIENT_REQ   	0x12
#define DBG_HEADER_CMD_CLIENT_ACK   	0x13
#define DBG_HEADER_CMD_BUFFER_WRITE 	0x14
#define DBG_HEADER_CMD_BUFFER_READ 	0x15
#define DBG_HEADER_CMD_RESPONSE    	0x16

#define DBG_AUX2_DONE			0x80
#define DBG_AUX2_RUNNING		0x40
#define DBG_AUX2_LLCACK			0x20
#define DBG_AUX2_TBREQ			0x10
#define DBG_AUX2_PAREN			0x08
#define DBG_AUX2_LAT_MASK		0x07

#define DBG_PARM_TIMEOUT		0x0
#define DBG_PARM_CREDITS		0x1
#define DBG_PARM_SEED   		0x2
#define DBG_PARM_RESP_PERCENT		0x3
#define DBG_PARM_PAGED_PERCENT		0x4
#define DBG_PARM_REORDER_PERCENT	0x5
#define DBG_PARM_BUFFER_PERCENT		0x6

size_t debug_get_64(FILE* fp, uint64_t *value);
size_t debug_get_32(FILE* fp, uint32_t *value);
size_t debug_get_16(FILE* fp, uint16_t *value);
size_t debug_get_8(FILE* fp, uint8_t *value);
DBG_HEADER debug_get_header(FILE* fp);

void debug_send_version(FILE* fp, uint8_t major, uint8_t minor);
void debug_afu_connect(FILE* fp, uint8_t id);
void debug_afu_drop(FILE* fp, uint8_t id);
void debug_cmd_add(FILE* fp, uint8_t id, uint8_t tag, uint16_t context,
		   uint16_t command);
void debug_cmd_update(FILE* fp, uint8_t id, uint8_t tag, uint16_t context,
		      uint16_t resp);
void debug_cmd_client(FILE* fp, uint8_t id, uint8_t tag, uint16_t context);
void debug_cmd_return(FILE* fp, uint8_t id, uint8_t tag, uint16_t context);
void debug_cmd_buffer_write(FILE* fp, uint8_t id, uint8_t tag);
void debug_cmd_buffer_read(FILE* fp, uint8_t id, uint8_t tag);
void debug_cmd_response(FILE* fp, uint8_t id, uint8_t tag);
void debug_context_add(FILE* fp, uint8_t id, uint16_t context);
void debug_context_remove(FILE* fp, uint8_t id, uint16_t context);
void debug_job_add(FILE* fp, uint8_t id, uint32_t code);
void debug_job_send(FILE* fp, uint8_t id, uint32_t code);
void debug_job_aux2(FILE* fp, uint8_t id, uint8_t aux2);
void debug_parm(FILE* fp, uint32_t parm, uint32_t value);
void debug_mmio_map(FILE* fp, uint8_t id, uint16_t context);
void debug_mmio_add(FILE* fp, uint8_t id, uint16_t context, uint8_t rnw,
		    uint8_t dw, uint32_t addr);
void debug_mmio_send(FILE* fp, uint8_t id, uint16_t context, uint8_t rnw,
		     uint8_t dw, uint32_t addr);
void debug_mmio_ack(FILE* fp, uint8_t id);
void debug_mmio_return(FILE* fp, uint8_t id, uint16_t context);
void debug_socket_put(FILE* fp, uint8_t id, uint16_t context, uint8_t type);
void debug_socket_get(FILE* fp, uint8_t id, uint16_t context, uint8_t type);

#endif /* _DEBUG_H_ */
