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
 * Description: MachineConfig.h
 *
 *  This file defines the MachineConfig class for the test AFU.
 */

#ifndef __machine_config_h__
#define __machine_config_h__

class MachineController::Machine::MachineConfig {

    /* machine config from MMIO writes and reads in format below: 
     * config[0]: enable_always(1) enable_once(1) reserved(1) command_code(13)|min_delay(16)|max_delay(16)|context(16)
     * config[1]: reserved(1) abort(3) command_size(12)| command_status(1) command_timestamp (15)|response_status(1) response_timestamp(15)|reserved(8) response_code(8)
     * config[2]: memory_base_address(64)
     * config[3]: memory_size(64) */
    uint64_t config[SIZE_CONFIG_TABLE];

    /* enable_always and enable_once are should be read from config[] directly
     * command/response status and timestamps and response_code are read only
     * ==== the following are configs to be read from MMIO at the end of each command ==== */

    /* sets the boundaries for the randomly selected delay, these fields are ignored in the enable_once mode */
    int
	max_delay;
    int
	min_delay;

    /* the "abort" entry when sending a command */
    uint8_t abort;

    /* the "command_size" entry when sending a command */
    uint16_t command_size;

    /* the "context" entry when sending a command, must not exceed the num_of_processes in the AFU descriptor */
    uint16_t context;

    /* specifies the valid memory space for this machine */
    uint64_t memory_base_address;
    uint64_t memory_size;

    /* ==== the above are configs to be read from MMIO at the end of each command ==== */

    /* private function to be called at the end of a command to update machine settings
     * in case the config space was changed */
    void
    read_machine_config ();

    void
    record_command (bool error_state, uint16_t cycle);
    void
    record_response ();

};
