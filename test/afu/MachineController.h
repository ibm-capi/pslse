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
 * Description: MachineController.h
 *
 *  This file defines the MachineController class for the test AFU.
 */

#ifndef __machine_controller_h__
#define __machine_controller_h__

extern "C" {
#include "psl_interface.h"
}
#include "TagManager.h"
#include <vector>
#include <map>
#define SIZE_CONFIG_TABLE 4
#define SIZE_CACHE_LINE 128
#define NUM_MACHINES 64
class MachineController {

	/* Machine class is made private inside Machine Controller so AFU only access machines through MachineController */
	class Machine;

	 std::vector < Machine * >machines;
	 std::map < uint32_t, Machine * >tag_to_machine;

	bool flushed_state;

 public:

	 MachineController();

	/* call this function every cylce (i.e. each iteration of while loop) in AFU.cpp 
	 * to send command from the first machine that has a command ready to be sent,
	 * highest priority is given to the 0th machine in the vector, then 1st, and 
	 * so on to provide a deterministic order for application to set up intersting
	 * test cases */
	void send_command(AFU_EVENT *, uint32_t cycle);

	/* call this function when AFU receives a response to pass the AFU_EVENT to 
	 * the corresponding machine and react appropriately*/
	void process_response(AFU_EVENT *, uint32_t cycle);

	/* call this function when AFU receives a buffer_write to pass the AFU_EVENT to 
	 * the corresponding machine and react appropriately*/
	void process_buffer_write(AFU_EVENT *);

	/* call this function when AFU receives a buffer_read to pass the AFU_EVENT to 
	 * the corresponding machine and react appropriately*/
	void process_buffer_read(AFU_EVENT *);

	/* call this function when AFU receives a normal MMIO write to modify machines */
	void change_machine_config(uint32_t word_address, uint32_t data);

	/* call this function when AFU receives a normal MMIO read to read machine config */
	uint32_t get_machine_config(uint32_t word_address);

	/* call this function to reset all the machines */
	void reset();

	/* call this function to see if any machine is still enabled */
	bool is_enabled() const;

	/* call this function to see if all machines with commands have already received a response */
	bool all_machines_completed() const;

	/* call this function to disable all machine when AFU receives a reset */
	void disable_all_machines();

	~MachineController();
};

#endif
