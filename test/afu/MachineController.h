#ifndef __machine_controller_h__
#define __machine_controller_h__

extern "C" {
#include "psl_interface.h"
#include "utils.h"
}

#include <vector>
#include <map>

#define SIZE_CONFIG_TABLE 4	// double words
#define SIZE_CACHE_LINE 128
#define NUM_MACHINES 64

class MachineController
{

    /* Machine class is made private inside Machine Controller so AFU only
     * access machines through MachineController */
    class Machine;

    bool flushed_state;

    std::vector < Machine * >machines;
    std::map < uint32_t, Machine * >tag_to_machine;

public:

    MachineController ();

    MachineController (uint16_t ctx);

    /* call this function every cylce (i.e. each iteration of while loop) in
     * AFU.cpp to send command from the first machine that has a command ready
     * to be sent, highest priority is given to the 0th machine in the vector,
     * then 1st, and so on to provide a deterministic order for application to
     * set up intersting test cases returns true if a command is actually sent,
     * false otherwise */
    bool send_command (AFU_EVENT *, uint32_t cycle);

    /* call this function when AFU receives a response to pass the AFU_EVENT to
     * the corresponding machine and react accordingly*/
    void process_response (AFU_EVENT *, uint32_t cycle);

    /* call this function when AFU receives a buffer_write to pass the
     * AFU_EVENT to the corresponding machine and react accordingly*/
    void process_buffer_write (AFU_EVENT *);

    /* call this function when AFU receives a buffer_read to pass the
     * AFU_EVENT to the corresponding machine and react accordingly*/
    void process_buffer_read (AFU_EVENT *);

    /* call this function when AFU receives a normal MMIO write to modify
     * machines */
    void change_machine_config (uint32_t word_address, uint64_t data,
                                uint32_t mmio_double);

    /* call this function when AFU receives a normal MMIO read to read machine
     * config */
    uint64_t get_machine_config (uint32_t word_address, uint32_t mmio_double);

    /* call this function to reset all the machines */
    void reset ();

    /* call this function to see if any machine is still enabled */
    bool is_enabled () const;

    /* call this function to see if all machines with commands have already
     * received a response */
    bool all_machines_completed () const;

    /* call this function to disable all machine when AFU receives a reset */
    void disable_all_machines ();

    /* call this function to find out if the tag belongs to this
     * machine controller */
    bool has_tag (uint32_t tag) const;

    ~MachineController ();
};

#endif
