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
	CMD_OTHER
};

enum mem_state {
	MEM_IDLE,
	MEM_TOUCH,
	MEM_TOUCHED,
	MEM_BUFFER,
	MEM_REQUEST,
	MEM_RECEIVED,
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
	uint32_t context;
	uint32_t command;
	uint32_t tag;
	uint32_t abt;
	uint32_t size;
	uint32_t resp;
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
	FILE *dbg_fp;
	uint8_t dbg_id;
	uint64_t lock_addr;
	uint64_t res_addr;
	uint32_t credits;
	uint16_t irq;
	int locked;
};

struct cmd *cmd_init(struct AFU_EVENT *afu_event, struct parms *parms,
		     struct mmio *mmio, volatile enum pslse_state *state,
		     FILE * dbg_fp, uint8_t dbg_id);

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

int client_cmd(struct cmd *cmd, struct client *client);

#endif				/* _CMD_H_ */
