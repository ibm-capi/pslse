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
 * Description: AFU.h
 *
 *  This file defines the AFU class for the test AFU.  This is the top level.
 */

#ifndef __afu_h__
#define __afu_h__

extern "C" {
#include "psl_interface.h"
#include "utils.h"
}
#include "Descriptor.h"
#include "TagManager.h"
#include "MachineController.h"
#include <string>
#include <vector>
class AFU {
	private:
		enum AFU_State { IDLE, RESET, READY, RUNNING,
			WAITING_FOR_LAST_RESPONSES
		};

		AFU_EVENT afu_event;
		Descriptor descriptor;

		MachineController machine_controller;

		AFU_State state;

		uint64_t mmio_regs[3];	// stores MMIO registers starting from address 0x200
		bool mmio_read_parity;	// AFU generates parity error if true

		int reset_delay;

		void resolve_aux1_event();
		void resolve_control_event();
		void resolve_mmio_descriptor_event();
		void resolve_mmio_event();
		void resolve_response_event(uint32_t cycle);
		void resolve_buffer_write_event();
		void resolve_buffer_read_event();

		void set_seed();
		void set_seed(uint32_t);

		void reset();

	public:
		/* constructor sets up descriptor from config file, establishes server socket connection 
		   and waits for client to connect */
		AFU(int port, std::string filename, bool parity);

		/* starts the main loop of the afu test platform */
		void start();

		/* destrutor close the socket connection */
		~AFU();

};

#endif
