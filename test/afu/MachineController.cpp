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
 * Description: MachineController.cpp
 *
 *  This file defines the MachineController class for the test AFU.
 */

#include "MachineController.h"
#include "Machine.h"

#include <stdlib.h>

MachineController::MachineController() : machines(NUM_MACHINES), tag_to_machine(){
	flushed_state = false;

	for(uint32_t i = 0; i < machines.size(); ++i)
		machines[i] = new Machine();
}

void MachineController::send_command(AFU_EVENT* afu_event, uint32_t cycle){
	bool try_send = true;

	uint32_t tag;
	if(!TagManager::request_tag(&tag)){
		debug_msg("MachineController::send_command: No more tags available");
		try_send = false;
	}

	for(uint32_t i = 0; i < machines.size(); ++i){
		if(machines[i]->is_enabled()){
			if(try_send && machines[i]->attempt_new_command(afu_event, tag, flushed_state, (uint16_t) (cycle & 0x7FFF))){
				// TODO debug message
				debug_msg("Machine id %d sent new command", i);
				try_send = false;
				tag_to_machine[tag] = machines[i];
			}
		}

		machines[i]->advance_cycle();
	}

	// tag was not used by any machine if try_send is still true therefore return it
	if(try_send)
		TagManager::release_tag(&tag);
}

void MachineController::process_response(AFU_EVENT* afu_event, uint32_t cycle){
	if(tag_to_machine.find(afu_event->response_tag) == tag_to_machine.end())
		error_msg("MachineController::process_response: Does not find corresponding machine for respone_tag");

	if(flushed_state && (afu_event->response_code == PSL_RESPONSE_AERROR || afu_event->response_code == PSL_RESPONSE_PAGED)) 
		error_msg("MachineController::process_response: another AERROR or PAGED response when the AFU is already in flush state");

	debug_msg("MachineController: Response code %d", afu_event->response_code);
	if(afu_event->response_code == PSL_RESPONSE_AERROR ||
			afu_event->response_code == PSL_RESPONSE_DERROR ||
			afu_event->response_code == PSL_RESPONSE_PAGED ){

		flushed_state = true;
		debug_msg("MachineController: AFU in flushed state");
		for(uint32_t i = 0; i < machines.size(); ++i)
			machines[i]->disable();
	}
	else if(afu_event->response_code == PSL_RESPONSE_DONE && tag_to_machine[afu_event->response_tag]->is_restart()){
		flushed_state = false;
	}
	else if(afu_event->response_code == PSL_RESPONSE_FLUSHED && !flushed_state){
		error_msg("MachineController: received FLUSHED response when AFU is not in flushed state");
	}

	tag_to_machine[afu_event->response_tag]->process_response(afu_event, flushed_state, (uint16_t) (cycle & 0x7FFF));
	TagManager::release_tag(&(afu_event->response_tag), afu_event->credits);
}

void MachineController::process_buffer_write(AFU_EVENT* afu_event){
	if(tag_to_machine.find(afu_event->buffer_write_tag) == tag_to_machine.end())
		error_msg("MachineController::process_buffer_write: Does not find corresponding machine for buffer_write_tag");

	tag_to_machine[afu_event->buffer_write_tag]->process_buffer_write(afu_event);
}

void MachineController::process_buffer_read(AFU_EVENT* afu_event){
	if(tag_to_machine.find(afu_event->buffer_read_tag) == tag_to_machine.end())
		error_msg("MachineController::process_buffer_read: Does not find corresponding machine for buffer_read_tag");

	tag_to_machine[afu_event->buffer_read_tag]->process_buffer_read(afu_event);
}

void MachineController::change_machine_config(uint32_t word_address, uint32_t data){
	// TODO modify to support double reads?
	uint32_t i = word_address / (SIZE_CONFIG_TABLE * 2);
	if(i >= NUM_MACHINES)
		//error_msg("MachineController::change_machine_config: word address exceeded machine configuration space");
		return;

	uint32_t offset = word_address % (SIZE_CONFIG_TABLE * 2);
	machines[i]->change_machine_config(offset, data);
}

uint32_t MachineController::get_machine_config(uint32_t word_address){
	uint32_t i = word_address / (SIZE_CONFIG_TABLE * 2);
	if(i >= NUM_MACHINES)
		//error_msg("MachineController::change_machine_config: word address exceeded machine configuration space");
		return 0xFFFFFFFF;

	uint32_t offset = word_address % (SIZE_CONFIG_TABLE * 2);
	return machines[i]->get_machine_config(offset);
}

void MachineController::reset(){
	TagManager::reset();
	flushed_state = false;
	for(uint32_t i = 0; i < machines.size(); ++i)
		machines[i]->reset();
}

bool MachineController::is_enabled() const{
	for(uint32_t i = 0; i < machines.size(); ++i)
		if(machines[i]->is_enabled()){
			debug_msg("Machine %d is still enabled", i);
			return true;
		}

	return false;
}

bool MachineController::all_machines_completed() const{
	for(uint32_t i = 0; i < machines.size(); ++i){
		if(!machines[i]->is_completed()){
			return false;
		}
	}

	return true;
}

void MachineController::disable_all_machines() {
	for(uint32_t i = 0; i < machines.size(); ++i)
		machines[i]->disable();
}

MachineController::~MachineController(){
	for(uint32_t i = 0; i < machines.size(); ++i)
		if(machines[i])
			delete machines[i];
}

