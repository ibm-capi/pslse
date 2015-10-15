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
 * Description: AFU.cpp
 *
 *  This file defines the AFU class for the test AFU.
 */

#include "AFU.h"

#include <string>
#include <stdio.h>
#include <iostream>
#include <stdlib.h>
#include <time.h>

using std::string;
using std::cout;
using std::endl;
using std::vector;

#define MACHINE_CONFIG_OFFSET 0x400

AFU::AFU(int port, string filename, bool parity) : descriptor(filename), machine_controller(){

	// initializes AFU socket connection as server
	if(psl_serv_afu_event(&afu_event, port) == PSL_BAD_SOCKET)
		error_msg("AFU: Unable to create socket");

	int parity_enable = parity;
	if(psl_afu_aux2_change(&afu_event, afu_event.job_running, afu_event.job_done, afu_event.job_cack_llcmd, afu_event.job_error, afu_event.job_yield, afu_event.timebase_request, parity_enable, 1) != PSL_SUCCESS){
		error_msg("AFU: Failed to set parity_enable and latency");
	}

	set_seed();

	state = IDLE;
	mmio_read_parity = false;

	for(uint32_t i = 0; i < 3; ++i)
		mmio_regs[i] = 0;

	reset_delay = 0;
}

void AFU::start(){
	uint32_t cycle = 0;
	while(1){
		fd_set watchset;
		FD_ZERO(&watchset);
		FD_SET(afu_event.sockfd, &watchset);
		select(afu_event.sockfd + 1, &watchset, NULL, NULL, NULL);
		int rc = psl_get_psl_events(&afu_event);

		++cycle;

		if(rc < 0){ // connection dropped
			info_msg("AFU: Connection lost");
			break;
		}

		if (rc <= 0) // no events to be processed
			continue;

		// job done should only be asserted for one cycle
		if(afu_event.job_done)
			afu_event.job_done = 0;

		// process event 
		if(afu_event.job_valid == 1){
			debug_msg("AFU: Received control event");
			resolve_control_event();
			afu_event.job_valid = 0;
		}

		if(afu_event.response_valid == 1){
			if(state != RUNNING && state != WAITING_FOR_LAST_RESPONSES && state != RESET)
				error_msg("AFU: Received response event when AFU is not running"); 

			debug_msg("AFU: Received response event");
			resolve_response_event(cycle);
			afu_event.response_valid = 0;
		}

		if(afu_event.mmio_valid == 1){
			if(afu_event.mmio_afudescaccess){
				if(state == IDLE || state == RESET)
					error_msg("AFU: Error MMIO descriptor access before AFU is done resetting");

				debug_msg("AFU: Received MMIO descriptor event");
				resolve_mmio_descriptor_event();
			}
			else{
				if(state != RUNNING && state != WAITING_FOR_LAST_RESPONSES)
					error_msg("AFU: Received MMIO non-descriptor access when AFU is not running"); 

				debug_msg("AFU: Received MMIO non-descriptor event");
				resolve_mmio_event();
			}
			afu_event.mmio_valid = 0;
		} 

		if(afu_event.buffer_write == 1){
			if(state != RUNNING && state != WAITING_FOR_LAST_RESPONSES && state != RESET)
				error_msg("AFU: Received buffer write when AFU is not running"); 

			debug_msg("AFU: Received buffer write event");
			resolve_buffer_write_event();
			afu_event.buffer_write = 0;
		}

		if(afu_event.buffer_read == 1){
			if(state != RUNNING && state != WAITING_FOR_LAST_RESPONSES && state != RESET)
				error_msg("AFU: Received buffer read event when AFU is not running"); 

			debug_msg("AFU: Received buffer read event");
			resolve_buffer_read_event();
			afu_event.buffer_read = 0;
		}

		if(afu_event.aux1_change == 1){
			debug_msg("AFU: aux1 change");
			resolve_aux1_event();
			afu_event.aux1_change = 0;
		}

		// generate commands
		if(state == RUNNING){
			machine_controller.send_command(&afu_event, cycle);
		}
		else if(state == RESET){
			if(reset_delay == 0){
				state = READY;
				reset();
				debug_msg("AFU: Sending job_done after reset");

				if(psl_afu_aux2_change(&afu_event, afu_event.job_running, 1, afu_event.job_cack_llcmd, afu_event.job_error, afu_event.job_yield, afu_event.timebase_request, afu_event.parity_enable, afu_event.buffer_read_latency) != PSL_SUCCESS){
					error_msg("AFU: Failed to assert job_done");
				}
			}
			else{
				if(reset_delay > 0)
					--reset_delay;
			}
		}
		else if(state == WAITING_FOR_LAST_RESPONSES){
			if(machine_controller.all_machines_completed()){
				debug_msg("AFU: All machines completed");
				machine_controller.reset();
				if(psl_afu_aux2_change(&afu_event, 0, 1, afu_event.job_cack_llcmd, afu_event.job_error, afu_event.job_yield, afu_event.timebase_request, afu_event.parity_enable, afu_event.buffer_read_latency) != PSL_SUCCESS)
					error_msg("AFU: Asserting done failed");
				state = IDLE;
			}
		}
	}
}

AFU::~AFU(){
	// close socket connection
	psl_close_afu_event(&afu_event);
}

void AFU::resolve_aux1_event(){
	if(state == RUNNING)
		error_msg("AFU: Changing \"room\" when AFU is running");

	TagManager::set_max_credits(afu_event.room);
}

void AFU::reset(){
	machine_controller.reset();

	for(uint32_t i = 0; i < 3; ++i)
		mmio_regs[i] = 0;
	mmio_read_parity = false;
}

void AFU::resolve_control_event(){
	// Check for job code parity
	if(afu_event.parity_enable)
		if(afu_event.job_code_parity != generate_parity(afu_event.job_code, ODD_PARITY))
			error_msg("AFU: Parity error in job_address");

	if(afu_event.job_code == PSL_JOB_RESET){
		debug_msg("AFU: Received RESET");
		if(psl_afu_aux2_change(&afu_event, 0, afu_event.job_done, afu_event.job_cack_llcmd, afu_event.job_error, afu_event.job_yield, afu_event.timebase_request, afu_event.parity_enable, afu_event.buffer_read_latency) != PSL_SUCCESS){
			error_msg("AFU: Failed to de-assert job_running");
		}
		machine_controller.disable_all_machines();
		state = RESET;
		reset_delay = 1000;
	}
	else if(afu_event.job_code == PSL_JOB_START){
		debug_msg("AFU: Start signal received in state %d", state);
		if(state != READY)
			error_msg("AFU: Start signal detected outside of READY state");
		mmio_regs[1] = afu_event.job_address;

		// Check for jea parity
		if(afu_event.parity_enable)
			if(afu_event.job_address_parity != generate_parity(afu_event.job_address, ODD_PARITY))
				error_msg("AFU: Parity error in job_address");

		// assert job_running
		if(psl_afu_aux2_change(&afu_event, 1, afu_event.job_done, afu_event.job_cack_llcmd, afu_event.job_error, afu_event.job_yield, afu_event.timebase_request, afu_event.parity_enable, afu_event.buffer_read_latency) != PSL_SUCCESS){
			error_msg("AFU: Failed to assert job_running");
		}

		state = RUNNING;
		debug_msg("AFU: AFU RUNNING");
	}
}

void AFU::resolve_mmio_descriptor_event(){
	if(afu_event.mmio_read){
		uint64_t data = 0;

		// double, 64 bits
		if(afu_event.mmio_double == 1){
			if(afu_event.mmio_address & 0x1) // address not even
				error_msg("AFU: Reading double word with non-even word address");

			data = descriptor.get_reg(afu_event.mmio_address);
		}
		// 32 bits
		else{ 
			data = descriptor.get_reg(afu_event.mmio_address & ~0x1);

			// duplicate the desired 32-bit data in both top and bottom 32 bits
			data = (data & 0xFFFFFFFF) | (data << 32);
		}

		uint32_t parity = (mmio_read_parity)? generate_parity(data + 1, 1):generate_parity(data, 1);
		if(psl_afu_mmio_ack(&afu_event, data, parity) != PSL_SUCCESS)
			error_msg("AFU: MMIO acknowledge failed");
	}
	else{
		error_msg("AFU: Descriptor write is not supported");
	}
}

void AFU::resolve_mmio_event(){

	// MMIO READ
	if(afu_event.mmio_read){
		uint64_t data = 0;

		// for driving parity
		if(afu_event.mmio_address == 0x4){
			if(afu_event.mmio_double)
				data = mmio_regs[2];
			else
				data = (mmio_regs[2] & 0xFFFFFFFF00000000) | (mmio_regs[2] >> 32);
			debug_msg("MMIO read parity data 0x%lx", data);
		}
		else if(afu_event.mmio_address == 0x2){
			data = mmio_regs[1];
		}
		else{
			if(afu_event.mmio_double){
				if(afu_event.mmio_address & 0x1) // address not even
					error_msg("AFU: Reading double word with non-even word address");

				data = machine_controller.get_machine_config(afu_event.mmio_address - MACHINE_CONFIG_OFFSET);
				data = (data << 32) | machine_controller.get_machine_config(afu_event.mmio_address-MACHINE_CONFIG_OFFSET+1);
				debug_msg("AFU: Read mmio data 64 address 0x%x, data %016lx", afu_event.mmio_address, data);
			}
			else{
				data = machine_controller.get_machine_config(afu_event.mmio_address - MACHINE_CONFIG_OFFSET);

				// duplicate the desired 32-bit data in both top and bottom 32 bits
				data = (data & 0xFFFFFFFF) | (data << 32);

				debug_msg("AFU: Read mmio data 32 address 0x%x, data %08lx", afu_event.mmio_address, data);

			}
		}
		uint32_t parity = (mmio_read_parity)? generate_parity(data + 1, 1):generate_parity(data, 1);
		if(psl_afu_mmio_ack(&afu_event, data, parity) != PSL_SUCCESS)
			error_msg("AFU: MMIO acknowledge failed");
	}
	// MMIO WRITE
	else{
		if(afu_event.mmio_address == 0x0){
			if(machine_controller.is_enabled())
				error_msg("AFU: Attempt to turn off AFU when one or more machines are still enabled");

			state = WAITING_FOR_LAST_RESPONSES;
			debug_msg("AFU: Preparing to shut down machine");
		}
		else if (afu_event.mmio_address == 0x2){
			error_msg("AFU should not write to this address");
		}
		else if (afu_event.mmio_address == 0x4){
			// TODO fix setting mmio_read_parity to false
			if( (afu_event.mmio_double && (afu_event.mmio_wdata & 0x8000000000000000)) || ((afu_event.mmio_double != 1) && (afu_event.mmio_wdata & 0x80000000))){
				mmio_read_parity = true;
				mmio_regs[2] = 0x8000000000000000;
				debug_msg("Setting MMIO read parity to 1");
			}
		}
		else{
			debug_msg("MMIO Write address 0x%lx", afu_event.mmio_address);
			if(afu_event.mmio_double == 1){
				machine_controller.change_machine_config(afu_event.mmio_address - MACHINE_CONFIG_OFFSET+1, afu_event.mmio_wdata & 0xFFFFFFFF);
				machine_controller.change_machine_config(afu_event.mmio_address - MACHINE_CONFIG_OFFSET, (afu_event.mmio_wdata & 0xFFFFFFFF00000000) >> 32);
				debug_msg("AFU: Write MMIO data 64 address 0x%x, data %016lx", afu_event.mmio_address, afu_event.mmio_wdata);
			}
			else{
				machine_controller.change_machine_config(afu_event.mmio_address - MACHINE_CONFIG_OFFSET, (afu_event.mmio_wdata & 0xFFFFFFFF));

				debug_msg("AFU: Write MMIO data 32 address 0x%x, data %08lx", afu_event.mmio_address, afu_event.mmio_wdata);
			}
		}
		if(psl_afu_mmio_ack(&afu_event, 0, 0) != PSL_SUCCESS)
			error_msg("AFU: MMIO acknowledge failed");
	}

}

void AFU::resolve_response_event(uint32_t cycle){
	if(!TagManager::is_in_use(&(afu_event.response_tag)))
		error_msg("AFU: Received tag not in use");

	machine_controller.process_response(&afu_event, cycle);
}

void AFU::resolve_buffer_write_event(){
	if(!TagManager::is_in_use(&(afu_event.buffer_write_tag)))
		error_msg("AFU: Received tag not in use");

	machine_controller.process_buffer_write(&afu_event);
}

void AFU::resolve_buffer_read_event(){
	if(!TagManager::is_in_use(&(afu_event.buffer_read_tag)))
		error_msg("AFU: Received tag not in use");

	machine_controller.process_buffer_read(&afu_event);
}

void AFU::set_seed(){
	srand(time(NULL));
}

void AFU::set_seed(uint32_t seed){
	srand(seed);
}
