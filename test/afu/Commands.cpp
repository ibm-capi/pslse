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
 * Description: Commands.cpp
 *
 *  This file defines the Command class for the test AFU.
 */

#include <stdlib.h>

#include "Commands.h"

Command::Command(uint16_t c, bool comm_addr_par, bool comm_code_par, bool comm_tag_par, bool buff_read_par) : code(c), completed(true), state(IDLE), command_address_parity(comm_addr_par), command_code_parity(comm_code_par), command_tag_parity(comm_tag_par), buffer_read_parity(buff_read_par) {}

bool Command::is_completed() const{
	return completed;
}

uint32_t Command::get_tag() const{
	return tag;
}

OtherCommand::OtherCommand(uint16_t c, bool comm_addr_par, bool comm_code_par, bool comm_tag_par, bool buff_read_par) : Command(c, comm_addr_par, comm_code_par, comm_tag_par, buff_read_par) {}

void OtherCommand::send_command(AFU_EVENT *afu_event, uint32_t new_tag, uint64_t address, uint16_t command_size, uint8_t abort, uint16_t context){
	if(Command::state != IDLE)
		error_msg("OtherCommand: Attempting to send command before previous command is completed");

	Command::completed = false;

	uint32_t tag_parity = generate_parity(new_tag, ODD_PARITY);
	uint32_t code_parity = generate_parity(Command::code, ODD_PARITY);
	uint32_t address_parity = generate_parity(address, ODD_PARITY);

	if (command_tag_parity)
		tag_parity = 1 - tag_parity;
	if (command_code_parity)
		code_parity = 1 - code_parity;
	if (command_address_parity)
		address_parity = 1 - address_parity;

	if(psl_afu_command(afu_event, new_tag, tag_parity, Command::code, code_parity, address, address_parity, command_size, abort, context) != PSL_SUCCESS)
		error_msg("OtherCommand: Failed to send command");

	// TODO may not need
	if(afu_event->command_valid)
		debug_msg("OtherCommand: handle=0x%x address=0x%016lx code=0x%04x size=0x%02x", context, address, Command::code, command_size);

	Command::state = WAITING_RESPONSE;
	Command::tag = new_tag;
}

void OtherCommand::process_response(AFU_EVENT *afu_event, uint8_t*){
	if(Command::state == IDLE){
		error_msg("OtherCommand: Attempt to process response when no command is currently active");
	}
	else if(Command::state == WAITING_RESPONSE){
		if(afu_event->response_valid == 1 && afu_event->response_tag == Command::tag){
			Command::completed = true;
			Command::state = IDLE;
		}
		else{
			error_msg("OtherCommand: Input not recognized");
		}
	}
	else{
		error_msg("OtherCommand: Should never be in this state");
	}
}

bool OtherCommand::is_restart() const{
	return (Command::code == 0x0001);
}

LoadCommand::LoadCommand(uint16_t c, bool comm_addr_par, bool comm_code_par, bool comm_tag_par, bool buff_read_par) : Command(c, comm_addr_par, comm_code_par, comm_tag_par, buff_read_par) {}

void LoadCommand::send_command(AFU_EVENT *afu_event, uint32_t new_tag, uint64_t address, uint16_t command_size, uint8_t abort, uint16_t context){
	if(Command::state != IDLE)
		error_msg("LoadCommand: Attempting to send command before previous command is completed");

	Command::completed = false;

	uint32_t tag_parity = generate_parity(new_tag, ODD_PARITY);
	uint32_t code_parity = generate_parity(Command::code, ODD_PARITY);
	uint32_t address_parity = generate_parity(address, ODD_PARITY);

	if (command_tag_parity)
		tag_parity = 1 - tag_parity;
	if (command_code_parity)
		code_parity = 1 - code_parity;
	if (command_address_parity)
		address_parity = 1 - address_parity;

	if(psl_afu_command(afu_event, new_tag, tag_parity, Command::code, code_parity, address, address_parity, command_size, abort, context) != PSL_SUCCESS)
		error_msg("LoadCommand: Failed to send command");

	debug_msg("LoadCommand: handle=0x%x address=0x%016lx code=0x%04x size=0x%02x", context, address, Command::code, command_size);
	Command::state = WAITING_DATA;
	Command::tag = new_tag;
}

void LoadCommand::process_response(AFU_EVENT *afu_event, uint8_t *cache_line){
	if(Command::state == WAITING_DATA){
		if(afu_event->buffer_write == 1 && afu_event->buffer_write_tag == Command::tag){
			process_buffer_write(afu_event, cache_line);
			afu_event->buffer_write = 0;

			Command::state = WAITING_RESPONSE;
			debug_msg("LoadCommand: Received buffer write in Waiting Data");
		}
		else if(afu_event->response_valid == 1 && afu_event->response_tag == Command::tag){
			Command::completed = true;
			Command::state = IDLE;
			debug_msg("LoadCommand: Received response");
		}
		else{
			error_msg("LoadCommand: Input not recognized, state: %d", WAITING_DATA);
		}
	}
	else if(Command::state == WAITING_RESPONSE){
		if(afu_event->buffer_write == 1 && afu_event->buffer_write_tag == Command::tag){
			process_buffer_write(afu_event, cache_line);
			debug_msg("LoadCommand: Received buffer write in Waiting response");
			afu_event->buffer_write = 0;
		}
		else if(afu_event->response_valid == 1 && afu_event->response_tag == Command::tag){
			Command::completed = true;
			Command::state = IDLE;
			debug_msg("LoadCommand: Received response");
		}
		else{
			error_msg("LoadCommand: Input not recognized, state %d, WAITING_RESPONSE");
		}
	}
	else if(Command::state == IDLE){
		error_msg("LoadCommand: Attempt to process response when no command is currently active");

	}
	else{
		error_msg("LoadCommand: Should never be in this state");
	}
}

void LoadCommand::process_buffer_write(AFU_EVENT *afu_event, uint8_t *cache_line){
	Command::state = WAITING_RESPONSE;

	memcpy(cache_line, afu_event->buffer_wdata, afu_event->buffer_write_length);

	if(afu_event->parity_enable){
		uint8_t parity[2];
		generate_cl_parity(cache_line, parity);
		for(int i = 0; i < 2; ++i)
			if(parity[i] != afu_event->buffer_wparity[i])
				error_msg("LoadCommand: Bad parity detected in buffer write");
	}

	debug_msg("BUFFER_WRITE:");
#ifdef DEBUG
	for(int i = 0; i < CACHELINE_BYTES; ++i) {
		if ((i % (CACHELINE_BYTES / 4)) == 0) {
			if (i > 0)
				printf("\n");
			printf(" Q%d 0x", i / (CACHELINE_BYTES / 4));
		}
		printf("%02x", cache_line[i]);
	}
	printf("\n");
#endif /* #ifdef DEBUG */
}

bool LoadCommand::is_restart() const{
	return false;
}

StoreCommand::StoreCommand(uint16_t c, bool comm_addr_par, bool comm_code_par, bool comm_tag_par, bool buff_read_par) : Command(c, comm_addr_par, comm_code_par, comm_tag_par, buff_read_par) {}


void StoreCommand::send_command(AFU_EVENT *afu_event, uint32_t new_tag, uint64_t address, uint16_t command_size, uint8_t abort, uint16_t context){
	if(Command::state != IDLE)
		error_msg("StoreCommand: Attempting to send command before previous command is completed");

	Command::completed = false;

	uint32_t tag_parity = generate_parity(new_tag, ODD_PARITY);
	uint32_t code_parity = generate_parity(Command::code, ODD_PARITY);
	uint32_t address_parity = generate_parity(address, ODD_PARITY);

	if (command_tag_parity)
		tag_parity = 1 - tag_parity;
	if (command_code_parity)
		code_parity = 1 - code_parity;
	if (command_address_parity)
		address_parity = 1 - address_parity;

	if(psl_afu_command(afu_event, new_tag, tag_parity, Command::code, code_parity, address, address_parity, command_size, abort, context) != PSL_SUCCESS)
		error_msg("StoreCommand: Failed to send command");

	debug_msg("StoreCommand: handle=0x%x address=0x%016lx code=0x%04x size=0x%02x", context, address, Command::code, command_size);

	Command::state = WAITING_READ;
	Command::tag = new_tag;
}

void StoreCommand::process_response(AFU_EVENT *afu_event, uint8_t *cache_line){
	if(Command::state == WAITING_READ){
		if(afu_event->buffer_read == 1 && afu_event->buffer_read_tag == Command::tag){
			process_buffer_read(afu_event, cache_line);
			afu_event->buffer_read = 0;
			Command::state = WAITING_RESPONSE;
		}
		else if(afu_event->response_valid == 1 && afu_event->response_tag == Command::tag){
			Command::completed = true;
			Command::state = IDLE;
		}
		else{
			error_msg("StoreCommand: Input not recognized");
		}
	}
	else if(Command::state == WAITING_RESPONSE){
		if(afu_event->buffer_read == 1 && afu_event->buffer_read_tag == Command::tag){
			process_buffer_read(afu_event, cache_line);
			afu_event->buffer_read = 0;
		}
		else if(afu_event->response_valid == 1 && afu_event->response_tag == Command::tag){
			Command::completed = true;
			Command::state = IDLE;
		}
		else{
			error_msg("StoreCommand: Input not recognized");
		}
	}
	else if(Command::state == IDLE){
		error_msg("StoreCommand: Atempt to process response when no command is currently active");
	}
	else{
		error_msg("StoreCommand: Should never be in this state");
	}

}

void StoreCommand::process_buffer_read(AFU_EVENT *afu_event, uint8_t *cache_line){
	uint8_t parity[2];
	generate_cl_parity(cache_line, parity);

	if(buffer_read_parity)
		parity[rand() % 2] += rand() % 256;

	if(psl_afu_read_buffer_data(afu_event, 128, cache_line, parity) != PSL_SUCCESS){
		error_msg("StoreCommand; failed to build buffer read data");
	}

	debug_msg("BUFFER_READ:");
#ifdef DEBUG
	for(int i = 0; i < CACHELINE_BYTES; ++i) {
		if ((i % (CACHELINE_BYTES / 4)) == 0) {
			if (i > 0)
				printf("\n");
			printf(" Q%d 0x", i / (CACHELINE_BYTES / 4));
		}
		printf("%02x", cache_line[i]);
	}
	printf("\n");
#endif /* #ifdef DEBUG */
}

bool StoreCommand::is_restart() const{
	return false;
}

