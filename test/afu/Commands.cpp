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
             address_parity,
#if defined	PSL9 || defined PSL9lite
	     command_size, abort, 0, 0)
#else 
	     command_size, abort, context) 
#endif
	     != PSL_SUCCESS)

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
    debug_msg("LoadCommand::send_command: command = 0x%x", Command::code);
    if (psl_afu_command
            (afu_event, new_tag, tag_parity, Command::code, code_parity, address,
             address_parity, 
#if defined PSL9 || defined PSL9lite
	     command_size, abort, context, 0)
#else
	      command_size, abort, context) 
#endif
	      != PSL_SUCCESS)
        error_msg ("LoadCommand: failed to send command");

    debug_msg ("LoadCommand::send_command: command sent");
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
            debug_msg ("LoadCommand::process_command: received buffer write in WAITING_DATA");
        }
        else if (afu_event->response_valid == 1
                 && afu_event->response_tag == Command::tag) {
            Command::completed = true;
            Command::state = IDLE;
            debug_msg ("LoadCommand::process_command: received response valid in WAITING_DATA");
        }
        else {
            error_msg ("LoadCommand::process_command: input not recognized, state: %d",
                       WAITING_DATA);
        }
    }
    else if (Command::state == WAITING_RESPONSE) {
        if (afu_event->buffer_write == 1
                && afu_event->buffer_write_tag == Command::tag) {
            process_buffer_write (afu_event, cache_line);
            debug_msg
            ("LoadCommand::process_command: received buffer write in WAITING_RESPONSE");
            afu_event->buffer_write = 0;
        }
        else if (afu_event->response_valid == 1
                 && afu_event->response_tag == Command::tag) {
            Command::completed = true;
            Command::state = IDLE;
            debug_msg ("LoadCommand::process_command: received response valid in WAITING_RESPONSE");
        }
        else {
            error_msg
            ("LoadCommand::process_command: input not recognized in WAITING_RESPONSE");
        }
    }
    else if (Command::state == IDLE) {
        error_msg
        ("LoadCommand::process_command: Attempt to process response when no command is currently active");

    }
    else {
        error_msg ("LoadCommand::process_command: should never be in this state");
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

    debug_msg("StoreCommand::send_command: command = 0x%x", Command::code);
    if (psl_afu_command
            (afu_event, new_tag, tag_parity, Command::code, code_parity,
             address, address_parity, 
#if defined PSL9 || PSL9lite
	     command_size, abort, context, 0)
#else
	     command_size, abort, context)
#endif
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
  
    debug_msg("SC::process_buffer_read: Buffer READ data");
    for (int i = 0; i < 15; ++i)
        debug_msg ("0x%x", cache_line[i]);
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
    uint16_t command_code;
    uint16_t i;

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
    if(Command::code == 0x1F00)
	command_code = 0x1F00;
    else {
	command_code = 0x1F01;
	// atomic add value
	for(i=0; i<8; i++) {
	    afu_event->dma0_req_data[i] = i;
	}
    }

//    command_code = 0x1F00;
    switch(Command::code) {
    case PSL_COMMAND_XLAT_RD_P0:
    case PSL_COMMAND_XLAT_RD_P1:
	afu_event->dma0_atomic_op = 0xFF;
	break;
    case PSL_COMMAND_XLAT_RD_P0_00:
	afu_event->dma0_atomic_op = 0x00;
	break;
    case PSL_COMMAND_XLAT_RD_P0_01:
	afu_event->dma0_atomic_op = 0x01;
	break;
    case PSL_COMMAND_XLAT_RD_P0_02:
	afu_event->dma0_atomic_op = 0x02;
	break;
    case PSL_COMMAND_XLAT_RD_P0_03:
	afu_event->dma0_atomic_op = 0x03;
	break;
    case PSL_COMMAND_XLAT_RD_P0_04:
	afu_event->dma0_atomic_op = 0x04;
	break;
    case PSL_COMMAND_XLAT_RD_P0_05:
	afu_event->dma0_atomic_op = 0x05;
	break;
    case PSL_COMMAND_XLAT_RD_P0_06:
	afu_event->dma0_atomic_op = 0x06;
	break;
    case PSL_COMMAND_XLAT_RD_P0_07:
	afu_event->dma0_atomic_op = 0x07;
	break;
    case PSL_COMMAND_XLAT_RD_P0_08:
	afu_event->dma0_atomic_op = 0x08;
	break;
    case PSL_COMMAND_XLAT_RD_P0_10:
	afu_event->dma0_atomic_op = 0x10;
	break;
    case PSL_COMMAND_XLAT_RD_P0_11:
	afu_event->dma0_atomic_op = 0x11;
	break;
    case PSL_COMMAND_XLAT_RD_P0_18:
	afu_event->dma0_atomic_op = 0x18;
	break;
    case PSL_COMMAND_XLAT_RD_P0_19:
	afu_event->dma0_atomic_op = 0x19;
	break;
    case PSL_COMMAND_XLAT_RD_P0_1C:
	afu_event->dma0_atomic_op = 0x1C;
	break;
    default:
	break;
    }
    // atomic ADD value	
    //for(i=0; i<8; i++) 
    //	afu_event->dma0_req_data[i] = i;
    debug_msg("DmaLoadCommand::send_command: calling psl_afu_command with");
    debug_msg("command_code = 0x%x  atomic_op = 0x%x", command_code, afu_event->dma0_atomic_op);
    if (psl_afu_command
            (afu_event, new_tag, tag_parity, command_code, code_parity, address,
             address_parity, command_size, abort, context, 0) != PSL_SUCCESS)
        error_msg ("DmaLoadCommand: failed to send command");
    
    Command::state = WAITING_DATA;
    Command::tag = new_tag;
    debug_msg("DmaLoadCommands::send_command: Command::state = WAITING_DATA");
}

void
DmaLoadCommand::process_command (AFU_EVENT * afu_event, uint8_t * cache_line)
{
    int i, psl_return;
    debug_msg("DMALC: state = %d", state);
    debug_msg("DMALC: dma0_completion_valid = %d", afu_event->dma0_completion_valid);
    debug_msg("DMALC: response_valid = %d", afu_event->response_valid);
    debug_msg("DMALC: utag = %d    command tag = %d", afu_event->dma0_req_utag, Command::tag);
    debug_msg("DMALC: dma0_sent_utag_valid = %d", afu_event->dma0_sent_utag_valid);
    debug_msg("DMALC: dma0_sent_utag_status = %d", afu_event->dma0_sent_utag_status);
    if (Command::state == WAITING_DATA) {
        if (afu_event->dma0_completion_valid == 1) {
            //    && afu_event->dma0_req_itag == Command::tag) {
	    debug_msg("DmaLoadCommand::process_command: call process_dma_write");
            process_dma_write (afu_event, cache_line);
            afu_event->dma0_dvalid = 0;
	    
            Command::state = WAITING_RESPONSE;
            debug_msg("DmaLoadCommand::process_command: Command::state = WAITING_DATA => WAITING_RESPONSE");
        }
        else if (afu_event->response_valid == 1 && afu_event->dma0_req_utag == Command::tag) {
            Command::completed = true;
            //Command::state = IDLE;
	    Command::state = WAITING_DATA;
 	    afu_event->dma0_req_itag = afu_event->response_dma0_itag;
	    debug_msg("DmaLoadCommand::process_command: Command::state = WAITING_DATA");
	    debug_msg("DmaLoadCommand::process_command: get itag from PSLSE = %x", afu_event->dma0_req_itag);
	    debug_msg("DmaLoadCommand::process_command: start DMA Read request");
	    if(afu_event->dma0_atomic_op == 0xFF) {
	     	afu_event->dma0_req_type = DMA_DTYPE_RD_REQ;
		//afu_event->dma0_req_size = 128;
	    }
	    else {
		afu_event->dma0_req_type = DMA_DTYPE_ATOMIC;
		afu_event->dma0_req_size = 8;
	    }
	    
	    debug_msg("DMA utag = 0x%x", afu_event->dma0_req_utag);
	    debug_msg("DMA itag = 0x%x", afu_event->dma0_req_itag);
	    debug_msg("DMA req type = %d", afu_event->dma0_req_type);
	    debug_msg("DMA req size = %d", afu_event->dma0_req_size);
	    debug_msg("DMA atomic op %d", afu_event->dma0_atomic_op);
	    debug_msg("DMA dma0_req_data");
	    for(i=0; i<8; i++) {
		//afu_event->dma0_req_data[i] = i;
		debug_msg("0x%02x",afu_event->dma0_req_data[i]);
	    }
	    
	    psl_return = psl_afu_dma0_req(afu_event, afu_event->dma0_req_utag, afu_event->dma0_req_itag,
			     afu_event->dma0_req_type, afu_event->dma0_req_size, 
			     afu_event->dma0_atomic_op, 0, afu_event->dma0_req_data);
	    
	    //afu_event->dma0_req_size = afu_event->dma0_req_size - 128;
	    debug_msg("DmaLoadCommand::process_command: psl_return = %d", psl_return);
	    debug_msg("DmaLoadCommand::process_command: dma0_req_size = 0x%x", afu_event->dma0_req_size);
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
            ("DmaLoadCommand::process_command: input not recognized in WAITING_RESPONSE state");
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
    printf("dma0_req_data = 0x");
    for(int i=0; i<=(int)(sizeof(afu_event->dma0_completion_data)-1); i++) {
  	afu_event->dma0_req_data[i] = afu_event->dma0_completion_data[i];
	printf("%02x", afu_event->dma0_req_data[i]);
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

    for (int i = 0; i < 8; ++i)
    {
        debug_msg ("DmaLoadCommand: received 0x%x for DMA write %d",
                   cache_line[i], i);
    }
    debug_msg ("DmaLoadCommand::processed_dma_write");
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
    uint16_t command_code;
    uint16_t i;

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
    if(Command::code != 0x1F01) {
	for(i=0; i<8; i++) {
	    afu_event->dma0_req_data[i] = i;
    	}
    }
    command_code = 0x1F01;
    switch(Command::code) {
    case PSL_COMMAND_XLAT_WR_P0:
    case PSL_COMMAND_XLAT_WR_P1:
	afu_event->dma0_atomic_op = 0xFF;
	break;
    case PSL_COMMAND_XLAT_WR_P0_20:
	afu_event->dma0_atomic_op = 0x20;
	break;
    case PSL_COMMAND_XLAT_WR_P0_21:
	afu_event->dma0_atomic_op = 0x21;
	break;
    case PSL_COMMAND_XLAT_WR_P0_22:
	afu_event->dma0_atomic_op = 0x22;
	break;
    case PSL_COMMAND_XLAT_WR_P0_23:
	afu_event->dma0_atomic_op = 0x23;
	break;
    case PSL_COMMAND_XLAT_WR_P0_24:
	afu_event->dma0_atomic_op = 0x24;
	break;
    case PSL_COMMAND_XLAT_WR_P0_25:
	afu_event->dma0_atomic_op = 0x25;
	break;
    case PSL_COMMAND_XLAT_WR_P0_26:
	afu_event->dma0_atomic_op = 0x26;
	break;
    case PSL_COMMAND_XLAT_WR_P0_27:
	afu_event->dma0_atomic_op = 0x27;
	break;
    case PSL_COMMAND_XLAT_WR_P0_38:
	afu_event->dma0_atomic_op = 0x38;
	break;
    default:
	break;
    }

    if (psl_afu_command
            (afu_event, new_tag, tag_parity, command_code, code_parity,
             address, address_parity, command_size, abort, context, 0)
            != PSL_SUCCESS) {
        error_msg ("DmaStoreCommand: failed to send command");
    }

    debug_msg ("DmaStoreCommand::send_command: command_code =  0x%x atomic_op = 0x%x sent", command_code, afu_event->dma0_atomic_op);
    Command::state = WAITING_READ;
    Command::tag = new_tag;
    debug_msg("DmaStoreCommand::send_command: Command State = WAITING_READ");
}

void
DmaStoreCommand::process_command (AFU_EVENT * afu_event, uint8_t * cache_line)
{
    int psl_return;
    debug_msg("DmaSC::process_command: dma0_sent_utag_valid = %d", afu_event->dma0_sent_utag_valid);
    debug_msg("DmaSC::process_command: dma0_sent_utag_status = %d", afu_event->dma0_sent_utag_status);
    debug_msg("DmaSC::process_command: response_valid = %d", afu_event->response_valid);
    debug_msg("DmaSC::process_command: dma0_atomic_op = 0x%x", afu_event->dma0_atomic_op);
    if (Command::state == WAITING_READ) {
	debug_msg("DmaSC::process_command: state = WAITING_READ");
        
	if (afu_event->dma0_sent_utag_status == 1) {
	    debug_msg("DmaSC::process_command: calling afu_get_dma0_sent_utag");
	    if(afu_get_dma0_sent_utag(afu_event, afu_event->dma0_req_utag, 
		afu_event->dma0_sent_utag_status) != PSL_SUCCESS)
			printf("AFU: Failed dma0_sent_utag_status\n");
	}
	else if (afu_event->response_valid == 1
                 && afu_event->response_tag == Command::tag) {
            Command::completed = true;
            //Command::state = IDLE;
	    debug_msg("DmaSC::process_command: Command state = IDLE in WAITING_READ");
 	    afu_event->dma0_req_itag = afu_event->response_dma0_itag;
	    debug_msg("DmaSC::process_command: dma0_req_itag = %x", afu_event->dma0_req_itag);
            debug_msg ("DmaSC::process_command: received response ");
	    debug_msg ("DmaSC::process_command: send DMA Write command request");
	    if(afu_event->dma0_atomic_op == 0xff) {
		afu_event->dma0_req_type = DMA_DTYPE_WR_REQ_128;
		//afu_event->dma0_req_size = 128;
	    }
	    else {
		afu_event->dma0_req_type = DMA_DTYPE_ATOMIC;
		afu_event->dma0_completion_type = DMA_CPL_TYPE_RD_128;
		afu_event->dma0_req_size = 8;
	    }

	    debug_msg("DMA utag = 0x%x", afu_event->dma0_req_utag);
	    debug_msg("DMA itag = 0x%x", afu_event->dma0_req_itag);
	    debug_msg("DMA req type = %d", afu_event->dma0_req_type);
	    debug_msg("DMA req size = %d", afu_event->dma0_req_size);
	    debug_msg("DMA atomic op = 0x%x", afu_event->dma0_atomic_op);
	    debug_msg("DMA dma0_req_data = 0x%x", afu_event->dma0_req_data);

	    psl_return = psl_afu_dma0_req(afu_event, afu_event->dma0_req_utag, afu_event->dma0_req_itag, 
                             afu_event->dma0_req_type, afu_event->dma0_req_size, 
			     afu_event->dma0_atomic_op, 0, afu_event->dma0_req_data);
	    debug_msg("DmaSC::process_command: psl_return = %d", psl_return);
	    //afu_event->dma0_req_size = afu_event->dma0_req_size - 128;
	    //debug_msg("DmaSC::process_command: dma0_req_size = %d", afu_event->dma0_req_size);
	    //afu_event->dma0_req_type = DMA_DTYPE_WR_REQ_MORE;

        }
        else {
            error_msg ("DmaSC: input not recognized");
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
	    debug_msg("DmaSC::process_command: Command state = IDLE in WAITING_RESPONSE");
        }
        else {
            error_msg ("DmaSC: input not recognized");
        }
    }
    else if (Command::state == IDLE) {
        error_msg
        ("DmaSC: Atempt to process response when no command is currently active");
    }
    else {
        error_msg ("DmaSC: should never be in this state");
    }
    debug_msg("DmaSC::process_command: end of function");
}

void
DmaStoreCommand::process_dma_read (AFU_EVENT * afu_event,
                                   uint8_t * cache_line)
{
//	int psl_return;
//    uint8_t parity[2];

    debug_msg("DmaStoreCommand::process_dma_read");
    //generate_cl_parity (cache_line, parity);

    //if (buffer_read_parity)
    //    parity[rand () % 2] += rand () % 256;
 	    debug_msg("DMA utag = 0x%x", afu_event->dma0_req_utag);
	    debug_msg("DMA itag = 0x%x", afu_event->dma0_req_itag);
	    debug_msg("DMA cpl type = %d", afu_event->dma0_completion_type);
	    debug_msg("DMA req size = 0x%x", afu_event->dma0_req_size);
    debug_msg("DmaStoreCommand::process_dma_read: dma0_atomic_op = 0x%x", afu_event->dma0_atomic_op);	   
    if (afu_event->dma0_atomic_op == 0xff) { 
	 if (afu_get_dma0_cpl_bus_data(afu_event, afu_event->dma0_sent_utag, afu_event->dma0_completion_type,
		afu_event->dma0_req_size, afu_event->dma0_completion_laddr,
		afu_event->dma0_completion_byte_count, cache_line) != PSL_SUCCESS) {
            error_msg ("DmaStoreCommand::process_dma_read: failed to build dma atomic read data");
   	}
    }
    else {
	debug_msg("DmaStoreCommand::process_dma_read: call afu_get_dma0_cpl_bus_data with no return");
	afu_get_dma0_cpl_bus_data(afu_event, afu_event->dma0_sent_utag, afu_event->dma0_completion_type,
		afu_event->dma0_req_size, afu_event->dma0_completion_laddr,
		afu_event->dma0_completion_byte_count, cache_line); 
    }

//    psl_return = afu_get_dma0_cpl_bus_data(afu_event, afu_event->dma0_sent_utag, afu_event->dma0_completion_type,
//		afu_event->dma0_req_size, afu_event->dma0_completion_laddr,
//		afu_event->dma0_completion_byte_count, cache_line);
//    debug_msg("DmaStoreCommand::process_dma_read: psl_return = %d", psl_return);
//    if (psl_return != PSL_SUCCESS ) {
    //if (afu_get_dma0_cpl_bus_data(afu_event, afu_event->dma0_sent_utag, afu_event->dma0_completion_type,
//		afu_event->dma0_req_size, afu_event->dma0_completion_laddr,
//		afu_event->dma0_completion_byte_count, cache_line) != PSL_SUCCESS) {
//        error_msg ("DmaStoreCommand::process_dma_read: failed to build dma atomic read data");
//    }
  
//    if (afu_get_dma0_cpl_bus_data(afu_event, afu_event->dma0_sent_utag, DMA_CPL_TYPE_RD_128,
//		128, afu_event->dma0_completion_laddr,
//		afu_event->dma0_completion_byte_count, cache_line) != PSL_SUCCESS) {
//      error_msg ("DmaStoreCommand::process_dma_read: failed to build dma atomic read data");
//    }


    for (int i = 0; i < 4; ++i)
        debug_msg ("DmaStoreCommand::process_dma_read: sending 0x%x for dma atomic read %d",
                   cache_line[i], i);
}

bool DmaStoreCommand::is_restart () const
{
    return
        false;
}

#endif	// PSL9



