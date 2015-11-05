#ifndef __descriptor_h__
#define __descriptor_h__

#include <string>
#include <stdint.h>
#include <vector>

extern "C" {
#include "utils.h"
}

#define MASK_IS_DEDICATED 0x8010
#define MASK_IS_DIRECTED 0x8004

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

    uint64_t get_reg (uint32_t word_address, uint32_t mmio_double) const;

    bool is_dedicated () const;
    bool is_directed () const;

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
