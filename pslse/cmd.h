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

#ifndef _CMD_H_
#define _CMD_H_

#include <stdint.h>
#include <stdio.h>

#include "client.h"
#include "mmio.h"
#include "parms.h"
#include "../common/psl_interface.h"

#define TOTAL_PAGES_CACHED 64
#define PAGE_WAYS 4
#define LOG2_WAYS 2		// log2(PAGE_WAYS) = log2(4) = 2
#define PAGE_ENTRIES (TOTAL_PAGES_CACHED / PAGE_WAYS)
#define LOG2_ENTRIES 4		// log2(PAGE_ENTRIES) = log2(64/4) = log2(16) = 4
#define PAGE_ADDR_BITS 12
#define PAGE_MASK 0xFFF

enum cmd_type {
	CMD_READ,
	CMD_WRITE,
	CMD_TOUCH,
	CMD_INTERRUPT,
	CMD_READ_PE,
//#ifdef PSL9
#if defined PSL9lite || defined PSL9
	CMD_CAS_4B,
	CMD_CAS_8B,
	CMD_CAIA2,
#endif
#ifdef PSL9
	CMD_XLAT_RD,
	CMD_XLAT_WR,
	CMD_DMA_RD,
	CMD_DMA_WR,
	CMD_DMA_WR_AMO,
	CMD_ITAG_ABRT_RD,
	CMD_ITAG_ABRT_WR,
	CMD_XLAT_RD_TOUCH,
	CMD_XLAT_WR_TOUCH,
#endif /* ifdef PSL9 define new cmd type */
	CMD_OTHER
};

enum mem_state {
	MEM_IDLE,
	MEM_TOUCH,
	MEM_TOUCHED,
	MEM_BUFFER,
	MEM_REQUEST,
#if defined PSL9 || PSL9lite
	MEM_CAS_OP,
	MEM_CAS_RD,
	MEM_CAS_WR,
#endif
	MEM_RECEIVED,
#ifdef PSL9
	DMA_ITAG_REQ,
	DMA_ITAG_RET,
	DMA_PENDING,
	DMA_PARTIAL,
	DMA_OP_REQ,
	DMA_SEND_STS,
	DMA_MEM_REQ,
	DMA_MEM_RESP,
	DMA_CPL_PARTIAL,
	DMA_CPL_SENT,
#endif /* ifdef PSL9 */
	MEM_DONE
};


struct pages {
	uint64_t entry[PAGE_ENTRIES][PAGE_WAYS];
	uint64_t entry_filter;
	uint64_t page_filter;
	int age[PAGE_ENTRIES][PAGE_WAYS];
	uint8_t valid[PAGE_ENTRIES][PAGE_WAYS];
};

struct cmd_event {
	uint64_t addr;
	int32_t context;
	uint32_t command;
	uint32_t tag;
	uint32_t abt;
	uint32_t size;
	uint32_t resp;
#if defined PSL9 || PSL9lite
	uint64_t cas_op1;
	uint64_t cas_op2;
	uint32_t cpagesize;
	uint32_t resp_r_pgsize;
	uint32_t resp_extra;
#endif // defined for both PSL9 & PSL9lite
#ifdef PSL9  //defined just for PSL9, ie DMA port related
	uint32_t port;
	uint32_t itag;
	uint32_t utag;
	uint32_t dsize;
	uint32_t dtype;
	uint32_t dpartial;
	uint32_t atomic_op;
	uint32_t sent_sts;
	uint32_t cpl_type;
	uint32_t cpl_size;
	uint32_t cpl_laddr;
	uint32_t cpl_byte_count;
	uint32_t cpl_xfers_to_go;
#endif /*ifdef PSL9 */
	uint8_t unlock;
	uint8_t buffer_activity;
	uint8_t *data;
	uint8_t *parity;
	int *abort;
	enum cmd_type type;
	enum mem_state state;
	enum client_state client_state;
	struct cmd_event *_next;
};

struct cmd {
	struct AFU_EVENT *afu_event;
	struct cmd_event *list;
	struct cmd_event *buffer_read;
	struct mmio *mmio;
	struct parms *parms;
	struct client **client;
	struct pages page_entries;
	volatile enum pslse_state *psl_state;
	char *afu_name;
	FILE *dbg_fp;
	uint8_t dbg_id;
	uint64_t lock_addr;
	uint64_t res_addr;
	uint32_t credits;
	int max_clients;
#if defined PSL9 || PSL9lite
	uint32_t pagesize;
#endif
	uint16_t irq;
	int locked;
};

struct cmd *cmd_init(struct AFU_EVENT *afu_event, struct parms *parms,
		     struct mmio *mmio, volatile enum pslse_state *state,
		     char *afu_name, FILE * dbg_fp, uint8_t dbg_id);

void handle_cmd(struct cmd *cmd, uint32_t parity_enabled, uint32_t latency);

void handle_buffer_read(struct cmd *cmd);

void handle_buffer_data(struct cmd *cmd, uint32_t parity_enable);

void handle_mem_write(struct cmd *cmd);

void handle_buffer_write(struct cmd *cmd);

void handle_touch(struct cmd *cmd);

void handle_interrupt(struct cmd *cmd);

void handle_mem_return(struct cmd *cmd, struct cmd_event *event, int fd);

void handle_aerror(struct cmd *cmd, struct cmd_event *event);

void handle_response(struct cmd *cmd);

//#ifdef PSL9
#if defined PSL9lite || defined PSL9
void handle_caia2_cmds(struct cmd *cmd);
void handle_dma0_read(struct cmd *cmd);
void handle_dma0_write(struct cmd *cmd);
void handle_dma0_sent_sts(struct cmd *cmd);
#endif /* ifdef PSL9 */


int client_cmd(struct cmd *cmd, struct client *client);

#endif				/* _CMD_H_ */
