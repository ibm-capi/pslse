#ifndef __machine_h__
#define __machine_h__

#include "Commands.h"
#include "TagManager.h"
#include "MachineController.h"

extern "C" {
#include "psl_interface.h"
#include "utils.h"
}

/* private class of MachineController declared in seperate file */

class MachineController::Machine {
private:
    Command * command;

    /* to keep the cache line of data from load and store command */
    uint8_t cache_line[SIZE_CACHE_LINE];

    /* machine randomly selects a number (between min_delay and max_delay)
     * of cycles to delay the generation of next command in the enable_always
     * mode, initial delay is always 0 */
    int delay;

    /* machine config from MMIO writes and reads in format defined in
     * AFU Test Driver documentation */
    uint64_t config[SIZE_CONFIG_TABLE];

    /* enable_always and enable_once are should be read from config[] directly
     * command/response status and timestamps and response_code are read only
     * ==== the following are configs to be read from MMIO at the end of each
     * command ==== */

    /* sets the boundaries for the randomly selected delay,
     * these fields are ignored in the enable_once mode */
    int max_delay;
    int min_delay;

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
    void read_machine_config ();

    void record_command (bool error_state, uint16_t cycle);
    void record_response (bool error_state, uint16_t cycle, uint8_t response_code);

    /* sets reponse code to FF to indicate that response_status,
     * reponse_timestamp are currently invalid */
    void clear_response ();

    /* clear the enable_once field in config */
    void disable_once ();

    /* returns the parity settings to decide whether to drive a parity error
     * in the following fields */
    uint8_t get_command_address_parity ()const;
    uint8_t get_command_code_parity ()const;
    uint8_t get_command_tag_parity ()const;
    uint8_t get_buffer_read_parity ()const;

public:
    Machine (uint16_t context);

    /* configures the machine when AFU receives an MMIO write, only modifies
     * the config array, machine reads the config right before the command
     * is sent */
    void change_machine_config (uint32_t offset, uint32_t data);

    /* returns a word from the configuration of machine depending on the
     * offset when AFU receives an MMIO read */
    uint32_t get_machine_config (uint32_t offset);

    /* notify advancement to next cycle to decrement delay, only decrement if
     * previous command has completed and if delay is not already 0 */
    void advance_cycle ();

    /* read config and send new command if the machine is ready to send a
     * command, returns true if a command is sent */
    bool attempt_new_command (AFU_EVENT *, uint32_t tag, bool error_state,
                              uint16_t cycle);

    /* process reponse received from simulator */
    void process_response (AFU_EVENT *, bool error_state, uint16_t cycle);

    /* process buffer write received from simulator */
    void process_buffer_write (AFU_EVENT *);

    /* process buffer read received from simulator */
    void process_buffer_read (AFU_EVENT *);

    /* clears BOTH the eanble_once and enable_always fields in config */
    void disable ();

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
    void reset ();

    ~Machine ();
};

#endif
