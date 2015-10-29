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
 * Description: Commands.cpp
 *
 *  This file defines the Command class for the test AFU.
 */

#ifndef __commands_h__
#define __commands_h__

extern "C"
{
#include "psl_interface.h"
#include "utils.h"
}
#include <stdint.h>
class Command
{
  protected:
    enum CommandStates
    { IDLE, WAITING_RESPONSE, WAITING_DATA,
	WAITING_READ
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
    //TODO change name
    virtual void process_response (AFU_EVENT *, uint8_t * cache_line) = 0;

    virtual bool is_restart () const = 0;

    bool is_completed () const;

    uint32_t get_tag () const;

      virtual ~ Command ()
    {
}};

class OtherCommand:public Command
{

  public:
    OtherCommand (uint16_t code, bool comm_addr_par, bool comm_code_par,
		  bool comm_tag_par, bool buff_read_par);

    void send_command (AFU_EVENT * afu_event, uint32_t new_tag,
		       uint64_t address, uint16_t command_size,
		       uint8_t abort, uint16_t context);

    void process_response (AFU_EVENT * afu_event, uint8_t *);

    bool is_restart () const;
};

class LoadCommand:public Command
{
  private:

    void process_buffer_write (AFU_EVENT * afu_event, uint8_t * cache_line);

  public:
      LoadCommand (uint16_t code, bool comm_addr_par, bool comm_code_par,
		   bool comm_tag_par, bool buff_read_par);

    void send_command (AFU_EVENT * afu_event, uint32_t new_tag,
		       uint64_t address, uint16_t command_size,
		       uint8_t abort, uint16_t context);

    void process_response (AFU_EVENT * afu_event, uint8_t * cache_line);

    bool is_restart () const;
};

class StoreCommand:public Command
{
  private:
    void process_buffer_read (AFU_EVENT * afu_event, uint8_t * cache_line);

  public:
      StoreCommand (uint16_t code, bool comm_addr_par, bool comm_code_par,
		    bool comm_tag_par, bool buff_read_par);

    void send_command (AFU_EVENT * afu_event, uint32_t new_tag,
		       uint64_t address, uint16_t command_size,
		       uint8_t abort, uint16_t context);

    void process_response (AFU_EVENT * afu_event, uint8_t * cache_line);

    bool is_restart () const;
};

#endif
