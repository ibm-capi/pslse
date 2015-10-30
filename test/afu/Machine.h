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
 * Description: Machine.h
 *
 *  This file defines the Machine class for the test AFU.
 */

#ifndef __machine_h__
#define __machine_h__

extern "C"
{
#include "psl_interface.h"
}
#include "Commands.h"
#include "TagManager.h"
#include "MachineController.h"
/* private class of MachineController declared in seperate file */
class
    MachineController::Machine
{
  private:
    Command * command;

    /* to keep the cache line of data from load and store command */
    uint8_t cache_line[SIZE_CACHE_LINE];

    /* machine randomly selects a number (between min_delay and max_delay) of
     * cycles to delay the generation of next command in the enable_always
     * mode, initial delay is always 0 */
    int
	delay;

    /* machine config from MMIO writes and reads in format below: 
     * config[0]: enable_always(1) enable_once(1) reserved(1) command_code(13)|min_delay(16)|max_delay(16)|context(16)
     * config[1]: reserved(1) abort(3) command_size(12)| command_status(1) command_timestamp (15)|response_status(1) response_timestamp(15)|reserved(8) response_code(8)
     * config[2]: memory_base_address(64)
     * config[3]: memory_size(64) */
    uint64_t config[SIZE_CONFIG_TABLE];

    /* enable_always and enable_once are should be read from config[] directly
     * command/response status and timestamps and response_code are read only
     * ==== the following are configs to be read from MMIO at the end of each
     * command ==== */

    /* sets the boundaries for the randomly selected delay, these fields are
     * ignored in the enable_once mode */
    int
	max_delay;
    int
	min_delay;

    /* the "abort" entry when sending a command */
    uint8_t abort;

    /* the "command_size" entry when sending a command */
    uint16_t command_size;

    /* the "context" entry when sending a command, must not exceed the
     * num_of_processes in the AFU descriptor */
    uint16_t context;

    /* specifies the valid memory space for this machine */
    uint64_t memory_base_address;
    uint64_t memory_size;

    /* ==== the above are configs to be read from MMIO at the end of each
     * command ==== */

    /* private function to be called at the end of a command to update machine
     * settings in case the config space was changed */
    void
    read_machine_config ();

    void
    record_command (bool error_state, uint16_t cycle);
    void
    record_response (bool error_state, uint16_t cycle, uint8_t response_code);

    /* sets reponse code to FF to indicate that response_status,
     * reponse_timestamp are currently invalid */
    void
    clear_response ();

    /* clear the enable_once field in config */
    void
    disable_once ();

    uint8_t get_command_address_parity ()const;

    uint8_t get_command_code_parity ()const;

    uint8_t get_command_tag_parity ()const;
    uint8_t get_buffer_read_parity ()const;

  public:
    Machine ();

    /* configures the machine when AFU receives an MMIO write, only modifies
     * the config space, machine reads the config right before the command is
     * sent */
    void
    change_machine_config (uint32_t offset, uint32_t data);

    /* depending on the offset, returns the configuration of machine when AFU
     * receives an MMIO read */
    uint32_t get_machine_config (uint32_t offset);

    /* notify advancement to next cycle to decrement delay, only decrement if 
     * previous command has completed and if delay is not already 0 */
    void
    advance_cycle ();

    /* read config and send new command if conditions are satisfied,
     * returns true if a command is sent */
    bool
    attempt_new_command (AFU_EVENT *, uint32_t tag, bool error_state,
			 uint16_t cycle);

    /* process reponse received from PSL */
    void
    process_response (AFU_EVENT *, bool error_state, uint16_t cycle);

    void
    process_buffer_write (AFU_EVENT *);

    void
    process_buffer_read (AFU_EVENT *);

    /* clear BOTH the eanble_once and enable_always fields in config */
    void
    disable ();

    /* returns true if either enable_once or enable_always is 1 */
    bool is_enabled ()const;

    /* returns true when enable_once is 1 */
    bool is_enabled_once ()const;

    /* returns true if the current command is completed,
     * i.e. in delayed phase */
    bool is_completed ()const;

    /* returns true if the current command is a restart command */
    bool is_restart ()const;

    /* resets the machine, clears the config space and cache line */
    void
    reset ();

    ~Machine ();
};

#endif
