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
 * Description: Machine.cpp
 *
 *  This file defines the Machine class for the test AFU.
 */

#include "Machine.h"
#include "MachineController.h"

#include <stdlib.h>

MachineController::Machine::Machine ()
{
    reset ();
}

void
MachineController::Machine::reset ()
{
    delay = 0;
    command = NULL;

    for (uint32_t i = 0; i < SIZE_CONFIG_TABLE; ++i)
	config[i] = 0;

    for (uint32_t i = 0; i < SIZE_CACHE_LINE; ++i)
	cache_line[i] = 0;
}

void
MachineController::Machine::read_machine_config ()
{

    context = (config[0] >> 32) & 0xFFFF;

    min_delay = (config[0] >> 16) & 0xFFFF;
    max_delay = config[0] & 0xFFFF;

    if (min_delay > max_delay)
	error_msg
	    ("Machine: min_delay is larger than max_delay (min_delay = %d, max_delay = %d)",
	     min_delay, max_delay);
    delay =
	(max_delay ==
	 min_delay) ? max_delay : rand () % (max_delay - min_delay) +
	min_delay;
    debug_msg ("Random delay: %d", delay);

    abort = (config[1] >> 60) & 0x7;
    command_size = (config[1] >> 48) & 0xFFF;

    memory_base_address = config[2];
    memory_size = config[3];

    uint16_t command_code = (config[0] >> 48) & 0x1FFF;

    bool command_address_parity = get_command_address_parity ();
    bool command_code_parity = get_command_code_parity ();
    bool command_tag_parity = get_command_tag_parity ();
    bool buffer_read_parity = get_buffer_read_parity ();

    if (command_address_parity)
	debug_msg ("Command address parity inject");
    if (command_code_parity)
	debug_msg ("Command code parity inject");
    if (command_tag_parity)
	debug_msg ("Command tag parity inject");
    if (buffer_read_parity)
	debug_msg ("Buffer read parity");

    if (command)
	delete command;

    switch (command_code) {
    case PSL_COMMAND_READ_CL_S:
    case PSL_COMMAND_READ_CL_M:
    case PSL_COMMAND_READ_CL_LCK:
    case PSL_COMMAND_READ_CL_RES:
    case PSL_COMMAND_READ_CL_NA:
    case PSL_COMMAND_READ_PNA:
    case PSL_COMMAND_READ_PE:
	command =
	    new LoadCommand (command_code, command_address_parity,
			     command_code_parity, command_tag_parity,
			     buffer_read_parity);
	break;
    case PSL_COMMAND_WRITE_MI:
    case PSL_COMMAND_WRITE_MS:
    case PSL_COMMAND_WRITE_UNLOCK:
    case PSL_COMMAND_WRITE_C:
    case PSL_COMMAND_WRITE_INJ:
    case PSL_COMMAND_WRITE_NA:
	command =
	    new StoreCommand (command_code, command_address_parity,
			      command_code_parity, command_tag_parity,
			      buffer_read_parity);
	break;
    case PSL_COMMAND_INTREQ:
    case PSL_COMMAND_RESTART:
    case PSL_COMMAND_FLUSH:
    case PSL_COMMAND_TOUCH_I:
    case PSL_COMMAND_TOUCH_S:
    case PSL_COMMAND_TOUCH_M:
    case PSL_COMMAND_PUSH_I:
    case PSL_COMMAND_PUSH_S:
    case PSL_COMMAND_EVICT_I:
    case PSL_COMMAND_LOCK:
    case PSL_COMMAND_UNLOCK:
	command =
	    new OtherCommand (command_code, command_address_parity,
			      command_code_parity, command_tag_parity,
			      buffer_read_parity);
	break;
    default:
	error_msg
	    ("MachineController::Machine::read_machine_config(): command code 0x%x is currently not supported",
	     command_code);
    }
}

void
MachineController::Machine::record_command (bool error_state, uint16_t cycle)
{
    debug_msg ("Command cycle count 0x%x", cycle);
    uint16_t data = (error_state) ? 1 << 15 : 0;

    data |= cycle & 0x7FFF;
    config[1] &= 0xFFFFFFFFFFFF0000;
    config[1] |= ((uint64_t) data);
}

void
MachineController::Machine::record_response (bool error_state, uint16_t cycle,
					     uint8_t response_code)
{
    debug_msg ("Response cycle count 0x%x", cycle);
    uint16_t data = (error_state) ? 1 << 15 : 0;

    data |= cycle & 0x7FFF;
    config[1] &= 0xFFFFFF000000FFFF;
    config[1] |= ((uint64_t) data << 16);
    config[1] |= ((uint64_t) response_code << 32);
}

void
MachineController::Machine::clear_response ()
{
    config[1] |= 0xFF00000000;
    debug_msg ("Machine: Clearing response");
}

     uint8_t MachineController::Machine::get_command_address_parity () const
     {
	 return (uint8_t) ((config[1] >> 47) & 0x1);
     }

uint8_t
     MachineController::Machine::get_command_code_parity () const
     {
	 return (uint8_t) ((config[1] >> 46) & 0x1);
     }

uint8_t
     MachineController::Machine::get_command_tag_parity () const
     {
	 return (uint8_t) ((config[1] >> 45) & 0x1);
     }

uint8_t
     MachineController::Machine::get_buffer_read_parity () const
     {
	 return (uint8_t) ((config[1] >> 44) & 0x1);
     }

     void
     MachineController::Machine::change_machine_config (uint32_t offset,
							uint32_t data)
{
    if (offset >= SIZE_CONFIG_TABLE * 2)
	error_msg
	    ("Machine::change_machine_config config table offset exceeded size of config table");

    // read only
    if (offset == 3) {
	return;
    }
    // lower 12 bits read only
    else if (offset == 2) {
	config[offset / 2] &= 0x00000FFFFFFFFFFF;
	config[offset / 2] |= ((uint64_t) (data & 0xFFFFF000) << 32);
    }
    else {
	if (offset % 2 == 1) {
	    config[offset / 2] &= 0xFFFFFFFF00000000;
	    config[offset / 2] |= (uint64_t) data;
	}
	else {
	    config[offset / 2] &= 0x00000000FFFFFFFF;
	    config[offset / 2] |= ((uint64_t) data << 32);
	}
    }
}

uint32_t MachineController::Machine::get_machine_config (uint32_t offset)
{
    if (offset >= SIZE_CONFIG_TABLE * 2)
	error_msg
	    ("Machine::change_machine_config config table offset exceeded size of config table");

    if (offset % 2 == 1)
	return (uint32_t) (config[offset / 2] & 0xFFFFFFFFL);
    else
	return (uint32_t) ((config[offset / 2] >> 32) & 0xFFFFFFFFL);
}

bool
MachineController::Machine::attempt_new_command (AFU_EVENT * afu_event,
						 uint32_t tag,
						 bool error_state,
						 uint16_t cycle)
{

    // only send new command if
    // 1. previous command has completed
    // 2. delay is 0
    // 3. a new tag is available

    if (!is_enabled ())
	error_msg
	    ("MachineController::Machine::attempt_new_command(): attemp to send new command when machine is not enabled");

    if ((!command || command->is_completed ()) && delay == 0) {
	read_machine_config ();

	//TODO randomly generates address within the range
	uint64_t address_offset;

	address_offset = (rand () % (memory_size - (command_size - 1)));
	address_offset &= ~(command_size - 1);

	command->send_command (afu_event, tag,
			       memory_base_address + address_offset,
			       command_size, abort, context);

	record_command (error_state, cycle);
	clear_response ();

	if (is_enabled_once ()) {
	    disable_once ();
	}

	return true;
    }

    return false;
}

void
MachineController::Machine::advance_cycle ()
{
    if (is_enabled () && (!command || command->is_completed ()) && delay > 0) {
	--delay;
	debug_msg ("Delay %d", delay);
    }

    if (!is_enabled ())
	delay = 0;
}

void
MachineController::Machine::process_response (AFU_EVENT * afu_event,
					      bool error_state,
					      uint16_t cycle)
{
    if (command->get_tag () != afu_event->response_tag)
	error_msg ("Machine: response_tag mismatches tag in machine");

    command->process_response (afu_event, cache_line);
    record_response (error_state, cycle, (uint8_t) afu_event->response_code);

    if (afu_event->response_code == PSL_RESPONSE_FLUSHED)
	disable ();
}

void
MachineController::Machine::process_buffer_write (AFU_EVENT * afu_event)
{
    if (command->get_tag () != afu_event->buffer_write_tag)
	error_msg ("Machine: buffer_write_tag mismatches tag in machine");

    command->process_response (afu_event, cache_line);
}

void
MachineController::Machine::process_buffer_read (AFU_EVENT * afu_event)
{
    if (command->get_tag () != afu_event->buffer_read_tag)
	error_msg ("Machine: buffer_read_tag mismatches tag in machine");

    command->process_response (afu_event, cache_line);
}

void
MachineController::Machine::disable_once ()
{
    config[0] &= ~0x4000000000000000;
}

void
MachineController::Machine::disable ()
{
    config[0] &= ~0xC000000000000000;
    delay = 0;
}

     bool MachineController::Machine::is_enabled () const
     {
	 bool
	     enable_always = ((config[0] >> 63) == 0x1);
	 bool
	     enable_once = (((config[0] >> 62) & 0x1) == 0x1);

	 return
	     enable_always ||
	     enable_once;
     }

bool
     MachineController::Machine::is_enabled_once () const
     {
	 bool
	     enable_once = ((config[0] >> 62) & 0x1);

	 return
	     enable_once;
     }

bool
     MachineController::Machine::is_completed () const
     {
	 if (!command || command->is_completed ())
	     return
		 true;

	 return
	     false;

     }

bool
     MachineController::Machine::is_restart () const
     {
	 if (!command)
	     error_msg
		 ("MachineController::Machine: calling command->is_restart() when command is not defined");
	 return
	     command->
	 is_restart ();
     }

MachineController::Machine::~
Machine ()
{
    if (command)
	delete command;
}
