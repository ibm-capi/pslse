#ifndef __commands_h__
#define __commands_h__

#include <stdint.h>

extern "C" {
#include "psl_interface.h"
#include "utils.h"
}

/* Command class - the base class of the three types of command: load, store, and others */
class Command
{
protected:
    enum CommandStates
    {
        IDLE, WAITING_RESPONSE, WAITING_DATA, WAITING_READ
    };

    const uint16_t code;
    bool completed;

    uint32_t tag;

    CommandStates state;

    bool command_address_parity;
    bool command_code_parity;
    bool command_tag_parity;
    bool buffer_read_parity;

public:

    Command (uint16_t code, bool comm_addr_par, bool comm_code_par,
             bool comm_tag_par, bool buff_read_par);

    virtual void send_command (AFU_EVENT *, uint32_t new_tag,
                               uint64_t address, uint16_t command_size,
                               uint8_t abort, uint16_t context) = 0;

    virtual void process_command (AFU_EVENT *, uint8_t * cache_line) = 0;

    virtual bool is_restart () const = 0;

    bool is_completed () const;

    uint32_t get_tag () const;

    virtual ~ Command ()
    {
    }
};

/* OtherCommand class - inherits from Command class,
 * used for all commands other than loads and stores */
class OtherCommand:public Command
{

public:
    OtherCommand (uint16_t code, bool comm_addr_par, bool comm_code_par,
                  bool comm_tag_par, bool buff_read_par);

    void send_command (AFU_EVENT * afu_event, uint32_t new_tag,
                       uint64_t address, uint16_t command_size, uint8_t abort,
                       uint16_t context);

    void process_command (AFU_EVENT * afu_event, uint8_t *);

    bool is_restart () const;
};

/* LoadComand class - inherits from Command class,
 * used for all load commands */
class LoadCommand:public Command
{
private:

    void process_buffer_write (AFU_EVENT * afu_event, uint8_t * cache_line);

public:
    LoadCommand (uint16_t code, bool comm_addr_par, bool comm_code_par,
                 bool comm_tag_par, bool buff_read_par);

    void send_command (AFU_EVENT * afu_event, uint32_t new_tag,
                       uint64_t address, uint16_t command_size, uint8_t abort,
                       uint16_t context);

    void process_command (AFU_EVENT * afu_event, uint8_t * cache_line);

    bool is_restart () const;
};

/* StoreCommand class - inherits from Command class,
 * used for all store commands */
class StoreCommand:public Command
{
private:
    void process_buffer_read (AFU_EVENT * afu_event, uint8_t * cache_line);

public:
    StoreCommand (uint16_t code, bool comm_addr_par, bool comm_code_par,
                  bool comm_tag_par, bool buff_read_par);

    void send_command (AFU_EVENT * afu_event, uint32_t new_tag,
                       uint64_t address, uint16_t command_size, uint8_t abort,
                       uint16_t context);

    void process_command (AFU_EVENT * afu_event, uint8_t * cache_line);

    bool is_restart () const;
};

#endif
