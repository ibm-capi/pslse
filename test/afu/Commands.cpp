#include <stdlib.h>

#include "Commands.h"

Command::Command (uint16_t c, bool comm_addr_par, bool comm_code_par, bool comm_tag_par, bool buff_read_par):code (c), completed (true), state (IDLE),
    command_address_parity (comm_addr_par), command_code_parity (comm_code_par),
    command_tag_parity (comm_tag_par), buffer_read_parity (buff_read_par)
{
}

bool Command::is_completed () const
{
    return
        completed;
}

uint32_t
Command::get_tag () const
{
    return tag;
}

OtherCommand::OtherCommand (uint16_t c, bool comm_addr_par,
                            bool comm_code_par, bool comm_tag_par,
                            bool buff_read_par):
    Command (c, comm_addr_par, comm_code_par, comm_tag_par, buff_read_par)
{
}

void
OtherCommand::send_command (AFU_EVENT * afu_event, uint32_t new_tag,
                            uint64_t address, uint16_t command_size,
                            uint8_t abort, uint16_t context)
{
    if (Command::state != IDLE)
        error_msg
        ("OtherCommand: Attempting to send command before previous command is completed");

    Command::completed = false;

    uint32_t tag_parity = generate_parity (new_tag, ODD_PARITY);

    if (command_tag_parity)
        tag_parity = 1 - tag_parity;

    uint32_t code_parity = generate_parity (Command::code, ODD_PARITY);

    if (command_code_parity)
        code_parity = 1 - code_parity;

    uint32_t address_parity = generate_parity (address, ODD_PARITY);

    if (command_address_parity)
        address_parity = 1 - address_parity;

    if (psl_afu_command
            (afu_event, new_tag, tag_parity, Command::code, code_parity, address,
             address_parity, command_size, abort, context) != PSL_SUCCESS)
        error_msg ("OtherCommand: failed to send command");

    if (afu_event->command_valid)
        debug_msg ("OtherCommand: command sent");

    Command::state = WAITING_RESPONSE;
    Command::tag = new_tag;
}

void
OtherCommand::process_command (AFU_EVENT * afu_event, uint8_t *)
{
    if (Command::state == IDLE) {
        error_msg
        ("OtherCommand: Attempt to process response when no command is currently active");
    }
    else if (Command::state == WAITING_RESPONSE) {
        if (afu_event->response_valid == 1
                && afu_event->response_tag == Command::tag) {
            Command::completed = true;
            Command::state = IDLE;
        }
        else {
            error_msg ("OtherCommand: input not recognized");
        }
    }
    else {
        error_msg ("OtherCommand: should never be in this state");
    }
}

bool OtherCommand::is_restart () const
{
    return (Command::code == PSL_COMMAND_RESTART);
}

LoadCommand::LoadCommand (uint16_t c, bool comm_addr_par, bool comm_code_par,
                          bool comm_tag_par, bool buff_read_par):
    Command (c, comm_addr_par, comm_code_par, comm_tag_par, buff_read_par)
{
}

void
LoadCommand::send_command (AFU_EVENT * afu_event, uint32_t new_tag,
                           uint64_t address, uint16_t command_size,
                           uint8_t abort, uint16_t context)
{
    if (Command::state != IDLE)
        error_msg
        ("LoadCommand: Attempting to send command before previous command is completed");

    Command::completed = false;

    uint32_t tag_parity = generate_parity (new_tag, ODD_PARITY);

    if (command_tag_parity)
        tag_parity = 1 - tag_parity;

    uint32_t code_parity = generate_parity (Command::code, ODD_PARITY);

    if (command_code_parity)
        code_parity = 1 - code_parity;

    uint32_t address_parity = generate_parity (address, ODD_PARITY);

    if (command_address_parity)
        address_parity = 1 - address_parity;

    if (psl_afu_command
            (afu_event, new_tag, tag_parity, Command::code, code_parity, address,
             address_parity, command_size, abort, context) != PSL_SUCCESS)
        error_msg ("LoadCommand: failed to send command");

    debug_msg ("LoadCommand: command sent");
    Command::state = WAITING_DATA;
    Command::tag = new_tag;
}

void
LoadCommand::process_command (AFU_EVENT * afu_event, uint8_t * cache_line)
{
    if (Command::state == WAITING_DATA) {
        if (afu_event->buffer_write == 1
                && afu_event->buffer_write_tag == Command::tag) {
            process_buffer_write (afu_event, cache_line);
            afu_event->buffer_write = 0;

            Command::state = WAITING_RESPONSE;
            debug_msg ("LoadCommand: received buffer write in Waiting Data");
        }
        else if (afu_event->response_valid == 1
                 && afu_event->response_tag == Command::tag) {
            Command::completed = true;
            Command::state = IDLE;
            debug_msg ("LoadCommand: received response");
        }
        else {
            error_msg ("LoadCommand: input not recognized, state: %d",
                       WAITING_DATA);
        }
    }
    else if (Command::state == WAITING_RESPONSE) {
        if (afu_event->buffer_write == 1
                && afu_event->buffer_write_tag == Command::tag) {
            process_buffer_write (afu_event, cache_line);
            debug_msg
            ("LoadCommand: received buffer write in Waiting response");
            afu_event->buffer_write = 0;
        }
        else if (afu_event->response_valid == 1
                 && afu_event->response_tag == Command::tag) {
            Command::completed = true;
            Command::state = IDLE;
            debug_msg ("LoadCommand: received response");
        }
        else {
            error_msg
            ("LoadCommand: input not recognized, state %d, WAITING_RESPONSE");
        }
    }
    else if (Command::state == IDLE) {
        error_msg
        ("LoadCommand: Attempt to process response when no command is currently active");

    }
    else {
        error_msg ("LoadCommand: should never be in this state");
    }
}

void
LoadCommand::process_buffer_write (AFU_EVENT * afu_event,
                                   uint8_t * cache_line)
{
    Command::state = WAITING_RESPONSE;

    memcpy (cache_line, afu_event->buffer_wdata,
            afu_event->buffer_write_length);

    if (afu_event->parity_enable) {
        uint8_t parity[2];

        generate_cl_parity (cache_line, parity);
        for (int i = 0; i < 2; ++i)
            if (parity[i] != afu_event->buffer_wparity[i])
                error_msg
                ("LoadCommand: bad parity detected in buffer write");
    }

    for (int i = 0; i < 4; ++i)
        debug_msg ("LoadCommand: received 0x%x for buffer write %d",
                   cache_line[i], i);
    debug_msg ("LoadCommand: processed_buffer_write");
}

bool LoadCommand::is_restart () const
{
    return
        false;
}

StoreCommand::StoreCommand (uint16_t c, bool comm_addr_par,
                            bool comm_code_par, bool comm_tag_par,
                            bool buff_read_par):
    Command (c, comm_addr_par, comm_code_par, comm_tag_par, buff_read_par)
{
}


void
StoreCommand::send_command (AFU_EVENT * afu_event, uint32_t new_tag,
                            uint64_t address, uint16_t command_size,
                            uint8_t abort, uint16_t context)
{
    if (Command::state != IDLE)
        error_msg
        ("StoreCommand: Attempting to send command before previous command is completed");

    Command::completed = false;

    uint32_t tag_parity = generate_parity (new_tag, ODD_PARITY);

    if (command_tag_parity)
        tag_parity = 1 - tag_parity;

    uint32_t code_parity = generate_parity (Command::code, ODD_PARITY);

    if (command_code_parity)
        code_parity = 1 - code_parity;

    uint32_t address_parity = generate_parity (address, ODD_PARITY);

    if (command_address_parity)
        address_parity = 1 - address_parity;

    if (psl_afu_command
            (afu_event, new_tag, tag_parity, Command::code, code_parity,
             address, address_parity, command_size, abort, context)
            != PSL_SUCCESS) {
        error_msg ("StoreCommand: failed to send command");
    }

    debug_msg ("StoreCommand: command sent");
    Command::state = WAITING_READ;
    Command::tag = new_tag;
}

void
StoreCommand::process_command (AFU_EVENT * afu_event, uint8_t * cache_line)
{
    if (Command::state == WAITING_READ) {
        if (afu_event->buffer_read == 1
                && afu_event->buffer_read_tag == Command::tag) {
            process_buffer_read (afu_event, cache_line);
            afu_event->buffer_read = 0;
            Command::state = WAITING_RESPONSE;
        }
        else if (afu_event->response_valid == 1
                 && afu_event->response_tag == Command::tag) {
            Command::completed = true;
            Command::state = IDLE;
        }
        else {
            error_msg ("StoreCommand: input not recognized");
        }
    }
    else if (Command::state == WAITING_RESPONSE) {
        if (afu_event->buffer_read == 1
                && afu_event->buffer_read_tag == Command::tag) {
            process_buffer_read (afu_event, cache_line);
            afu_event->buffer_read = 0;
        }
        else if (afu_event->response_valid == 1
                 && afu_event->response_tag == Command::tag) {
            Command::completed = true;
            Command::state = IDLE;
        }
        else {
            error_msg ("StoreCommand: input not recognized");
        }
    }
    else if (Command::state == IDLE) {
        error_msg
        ("StoreCommand: Atempt to process response when no command is currently active");
    }
    else {
        error_msg ("StoreCommand: should never be in this state");
    }

}

void
StoreCommand::process_buffer_read (AFU_EVENT * afu_event,
                                   uint8_t * cache_line)
{
    uint8_t parity[2];

    generate_cl_parity (cache_line, parity);

    if (buffer_read_parity)
        parity[rand () % 2] += rand () % 256;

    if (psl_afu_read_buffer_data (afu_event, 128, cache_line, parity) !=
            PSL_SUCCESS) {
        error_msg ("StoreCommand; failed to build buffer read data");
    }

    for (int i = 0; i < 4; ++i)
        debug_msg ("StoreCommand: sending 0x%x for buffer read %d",
                   cache_line[i], i);
    debug_msg ("StoreCommand: processed_buffer_read");
}

bool StoreCommand::is_restart () const
{
    return
        false;
}


#ifdef	PSL9
DmaLoadCommand::DmaLoadCommand (uint16_t c, bool comm_addr_par, bool comm_code_par,
                          bool comm_tag_par, bool buff_read_par):
    Command (c, comm_addr_par, comm_code_par, comm_tag_par, buff_read_par)
{
    debug_msg("DmaLoadCommand: Constructor");
}

void
DmaLoadCommand::send_command (AFU_EVENT * afu_event, uint32_t new_tag,
                           uint64_t address, uint16_t command_size,
                           uint8_t abort, uint16_t context)
{
    if (Command::state != IDLE)
        error_msg
        ("DmaLoadCommand: Attempting to send command before previous command is completed");

    Command::completed = false;

    uint32_t tag_parity = generate_parity (new_tag, ODD_PARITY);

    if (command_tag_parity)
        tag_parity = 1 - tag_parity;

    uint32_t code_parity = generate_parity (Command::code, ODD_PARITY);

    if (command_code_parity)
        code_parity = 1 - code_parity;

    uint32_t address_parity = generate_parity (address, ODD_PARITY);

    if (command_address_parity)
        address_parity = 1 - address_parity;

    if (psl_afu_command
            (afu_event, new_tag, tag_parity, Command::code, code_parity, address,
             address_parity, command_size, abort, context) != PSL_SUCCESS)
        error_msg ("DmaLoadCommand: failed to send command");
    debug_msg ("DmaLoadCommand::send_command: 0x%x command sent", Command::code);
    Command::state = WAITING_DATA;
    Command::tag = new_tag;
    debug_msg("DmaLoadCommands::send_command: Command::state = WAITING_DATA");
}

void
DmaLoadCommand::process_command (AFU_EVENT * afu_event, uint8_t * cache_line)
{
    if (Command::state == WAITING_DATA) {
        if (afu_event->dma0_completion_valid == 1) {
            //    && afu_event->dma0_req_itag == Command::tag) {
            process_dma_write (afu_event, cache_line);
            afu_event->dma0_dvalid = 0;
	    
            Command::state = WAITING_RESPONSE;
            debug_msg("DmaLoadCommand::process_command: Command::state = WAITING_RESPONSE");
	    debug_msg ("DmaLoadCommand: received DMA write in Waiting Data");
        }
        else if (afu_event->response_valid == 1 && afu_event->dma0_req_utag == Command::tag) {
            Command::completed = true;
            //Command::state = IDLE;
	    Command::state = WAITING_DATA;
 	    afu_event->dma0_req_itag = afu_event->response_dma0_itag;
	    debug_msg("DmaLoadCommand::process_command: Command::state = WAITING_DATA");
	    debug_msg("DmaLoadCommand::process_command: get itag from PSLSE = %x", afu_event->dma0_req_itag);
	    debug_msg("DmaLoadCommand::process_command: start DMA Read request");
	    debug_msg("with utag = %d : DMA req type = %d : Data = 0x%x", afu_event->dma0_req_utag,
			DMA_DTYPE_RD_REQ, afu_event->dma0_req_data);
	    psl_afu_dma0_req(afu_event, afu_event->dma0_req_utag, afu_event->dma0_req_itag,
			     DMA_DTYPE_RD_REQ, 128, afu_event->dma0_req_data);

        }
        else {
            error_msg ("DmaLoadCommand: input not recognized, state: %d",
                       WAITING_DATA);
        }
    }
    else if (Command::state == WAITING_RESPONSE) {
        if (afu_event->dma0_sent_utag_valid == 1) {
             //   && afu_event->dma0_req_itag == Command::tag) {
            process_dma_write (afu_event, cache_line);
            debug_msg
            ("DmaLoadCommand: received DMA write in Waiting response");
            afu_event->dma0_dvalid = 0;
        }
        else if (afu_event->response_valid == 1
                 && afu_event->response_tag == Command::tag) {
            Command::completed = true;
            Command::state = IDLE;
	    debug_msg("DmaLoadCommand::process_command: Command::state = IDLE");
        }
        else {
            error_msg
            ("DmaLoadCommand: input not recognized, state %d, WAITING_RESPONSE");
        }
    }
    else if (Command::state == IDLE) {
        error_msg
        ("DmaLoadCommand: Attempt to process response when no command is currently active");

    }
    else {
        error_msg ("DmaLoadCommand: should never be in this state");
    }
}

void
DmaLoadCommand::process_dma_write (AFU_EVENT * afu_event,
                                   uint8_t * cache_line)
{
    Command::state = WAITING_RESPONSE;
    debug_msg("DmaLoadCommand::process_dma_write: Command state = WAITING_RESPONSE");
    for(int i=0; i<=(sizeof(afu_event->dma0_completion_data)-1); i++) {
  	afu_event->dma0_req_data[i] = afu_event->dma0_completion_data[i];
    }

    memcpy (cache_line, afu_event->dma0_req_data,
            afu_event->dma0_req_size);

    if (afu_event->parity_enable) {
        uint8_t parity[2];

        generate_cl_parity (cache_line, parity);
        for (int i = 0; i < 2; ++i)
            if (parity[i] != afu_event->buffer_wparity[i])
                error_msg
                ("DmaLoadCommand: bad parity detected in DMA write");
    }

    for (int i = 0; i < 4; ++i)
    {
        debug_msg ("DmaLoadCommand: received 0x%x for DMA write %d",
                   cache_line[i], i);
    }
    debug_msg ("DmaLoadCommand: processed_dma_write");
}

bool DmaLoadCommand::is_restart () const
{
    return
        false;
}

DmaStoreCommand::DmaStoreCommand (uint16_t c, bool comm_addr_par,
                            bool comm_code_par, bool comm_tag_par,
                            bool buff_read_par):
    Command (c, comm_addr_par, comm_code_par, comm_tag_par, buff_read_par)
{
}


void
DmaStoreCommand::send_command (AFU_EVENT * afu_event, uint32_t new_tag,
                            uint64_t address, uint16_t command_size,
                            uint8_t abort, uint16_t context)
{
    if (Command::state != IDLE)
        error_msg
        ("DmaStoreCommand: Attempting to send command before previous command is completed");

    Command::completed = false;

    uint32_t tag_parity = generate_parity (new_tag, ODD_PARITY);

    if (command_tag_parity)
        tag_parity = 1 - tag_parity;

    uint32_t code_parity = generate_parity (Command::code, ODD_PARITY);

    if (command_code_parity)
        code_parity = 1 - code_parity;

    uint32_t address_parity = generate_parity (address, ODD_PARITY);

    if (command_address_parity)
        address_parity = 1 - address_parity;

    if (psl_afu_command
            (afu_event, new_tag, tag_parity, Command::code, code_parity,
             address, address_parity, command_size, abort, context)
            != PSL_SUCCESS) {
        error_msg ("DmaStoreCommand: failed to send command");
    }

    debug_msg ("DmaStoreCommand::send_command: 0x%x command sent", Command::code);
    Command::state = WAITING_READ;
    Command::tag = new_tag;
    debug_msg("DmaStoreCommand::send_command: Command State = WAITING_READ");
}

void
DmaStoreCommand::process_command (AFU_EVENT * afu_event, uint8_t * cache_line)
{
    debug_msg("DmaStoreCommand::process_command");
    debug_msg("DmaStoreCommand::process_command: dma0_sent_utag_valid = %d", afu_event->dma0_sent_utag_status);
    if (Command::state == WAITING_READ) {
	debug_msg("DmaStoreCommand::process_command: state = WAITING_READ");
        if (afu_event->dma0_sent_utag_valid == 0x1) {
              //  && afu_event->dma0_req_itag == Command::tag) {
            process_dma_read (afu_event, cache_line);
            afu_event->dma0_dvalid = 0;
            Command::state = WAITING_RESPONSE;
	    debug_msg("DmaStoreCommand::process_command: Command state = WAITING_RESPONSE");
        }
        else if (afu_event->response_valid == 1
                 && afu_event->response_tag == Command::tag) {
            Command::completed = true;
            //Command::state = IDLE;
	    debug_msg("DmaStoreCommand::process_command: Command state = IDLE in WAITING_READ");
 	    afu_event->dma0_req_itag = afu_event->response_dma0_itag;
	    debug_msg("DmaStoreCommand::process_command: dma0_req_itag = %x", afu_event->dma0_req_itag);
            debug_msg ("DmaStoreCommand::process_command: received response ");
	    debug_msg ("DmaStoreCommand::process_command: send DMA Write command request");
	    psl_afu_dma0_req(afu_event, afu_event->dma0_req_utag, afu_event->dma0_req_itag, 
                             DMA_DTYPE_WR_REQ_128, 128, afu_event->dma0_req_data);

        }
        else {
            error_msg ("DmaStoreCommand: input not recognized");
        }
    }
    else if (Command::state == WAITING_RESPONSE) {
        if (afu_event->dma0_sent_utag_valid == 1) {
              //  && afu_event->dma0_req_itag == Command::tag) {
            process_dma_read (afu_event, cache_line);
            afu_event->dma0_dvalid = 0;
        }
        else if (afu_event->response_valid == 1
                 && afu_event->response_tag == Command::tag) {
            Command::completed = true;
            Command::state = IDLE;
	    debug_msg("DmaStoreCommand::process_command: Command state = IDLE in WAITING_RESPONSE");
        }
        else {
            error_msg ("DmaStoreCommand: input not recognized");
        }
    }
    else if (Command::state == IDLE) {
        error_msg
        ("DmaStoreCommand: Atempt to process response when no command is currently active");
    }
    else {
        error_msg ("DmaStoreCommand: should never be in this state");
    }
    debug_msg("DmaStoreCommand::process_command: end of function");
}

void
DmaStoreCommand::process_dma_read (AFU_EVENT * afu_event,
                                   uint8_t * cache_line)
{
    uint8_t parity[2];

    debug_msg("DmaStoreCommand::process_dma_read");
    //generate_cl_parity (cache_line, parity);

    //if (buffer_read_parity)
    //    parity[rand () % 2] += rand () % 256;

    if (afu_get_dma0_cpl_bus_data(afu_event, afu_event->dma0_sent_utag, 0,128, cache_line) !=
            PSL_SUCCESS) {
        error_msg ("DmaStoreCommand::process_dma_read: failed to build dma read data");
    }

    for (int i = 0; i < 4; ++i)
        debug_msg ("DmaStoreCommand::process_dma_read: sending 0x%x for dma read %d",
                   cache_line[i], i);
}

bool DmaStoreCommand::is_restart () const
{
    return
        false;
}

#endif	// PSL9



