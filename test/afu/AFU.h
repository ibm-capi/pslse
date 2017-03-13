#ifndef __afu_h__
#define __afu_h__

#include "Descriptor.h"
#include "TagManager.h"
#include "MachineController.h"

extern "C" {
#include "psl_interface.h"
#include "utils.h"
}

#include <string>
#include <vector>

class AFU
{
private:
    enum AFU_State
    { IDLE, RESET, READY, RUNNING, WAITING_FOR_LAST_RESPONSES };

    AFU_EVENT afu_event;
    Descriptor descriptor;

    std::map < uint16_t, MachineController * >context_to_mc;
    std::map < uint16_t,
        MachineController * >::iterator highest_priority_mc;

    MachineController *machine_controller;

    AFU_State state;

    uint64_t global_configs[3];	// stores MMIO registers for global configurations

    int reset_delay;

    void resolve_aux1_event ();
    void resolve_control_event ();
    void resolve_mmio_descriptor_event ();
    void resolve_mmio_event ();
    void resolve_response_event (uint32_t cycle);
    void resolve_buffer_write_event ();
    void resolve_buffer_read_event ();
#ifdef	PSL9
    void resolve_dma_read_event ();
    void resolve_dma_write_event ();
#endif
    void set_seed ();
    void set_seed (uint32_t);

    void reset ();
    void reset_machine_controllers ();

    bool get_mmio_read_parity ();
    bool set_jerror_not_run;

public:
    /* constructor sets up descriptor from config file, establishes server socket connection
       and waits for client to connect */
    AFU (int port, std::string filename, bool parity, bool jerror);

    /* starts the main loop of the afu test platform */
    void start ();

    /* destrutor close the socket connection */
    ~AFU ();

};


#endif
