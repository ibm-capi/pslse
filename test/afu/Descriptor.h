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
 * Description: Descriptor.h
 *
 *  This file defines the Descriptor class for the test AFU.
 */

#ifndef __descriptor_h__
#define __descriptor_h__

#include <string>
#include <stdint.h>
#include <vector>

extern "C"
{
#include "utils.h"
}
//TODO possibly adding macros for each fields//#define MASK_NUM_OF_PROCESS  
#define DESCRIPTOR_NUM_REGS 10
class Descriptor
{
  private:
    std::vector < uint64_t > regs;
    /*  reg0x00 : [0:15]  num_ints_per_process
       [16:31] num_of_process
       [32:47] num_of_afu_CRs
       [48:63] reg_prog_model 

       reg0x08 - reg0x18 RESERVED

       reg0x20 : [0:7]  RESERVED
       [8:63] AFU_CR_len

       reg0x28 : [0:63] AFU_CR_offset

       reg0x30 : [0:7]  PerProcessPSA_control
       [8:63] PerProcessPSA_length

       reg0x38 : [0:63] PerProcessPSA_offset

       reg0x40 : [0:7]  RESERVED
       [8:63] AFU_EB_len

       reg0x48 : [0:63] AFU_EB_offset
     */

    void parse_descriptor_file (std::string filename);
    uint32_t to_vector_index (uint32_t byte_address) const;

  public:
      Descriptor (std::string filename);

    uint64_t get_reg (uint32_t word_address) const;

    // reg0x00
    uint16_t get_num_ints_per_process () const;
    uint16_t get_num_of_process () const;
    uint16_t get_num_of_afu_CRs () const;
    uint16_t get_reg_prog_model () const;

    // reg0x20
    uint64_t get_AFU_CR_len () const;

    //reg0x28
    uint64_t get_AFU_CR_offset () const;

    // reg0x30
    uint8_t get_PerProcessPSA_control () const;
    uint64_t get_PerProcessPSA_length () const;

    // reg0x38
    uint64_t get_PerProcessPSA_offset () const;

    // reg0x40
    uint64_t get_AFU_EB_len () const;

    // reg0x48
    uint64_t get_AFU_EB_offset () const;

};

#endif
