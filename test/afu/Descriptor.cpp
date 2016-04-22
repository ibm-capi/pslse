#include "Descriptor.h"

#include <limits.h>
#include <string>
#include <stdlib.h>
#include <stdint.h>
#include <fstream>
#include <sstream>

using std::string;
using std::ifstream;
using std::stringstream;

Descriptor::Descriptor (string filename):regs (DESCRIPTOR_NUM_REGS)
{
    info_msg ("Descriptor: attempting to set up descriptor with %s",
              filename.c_str ());
    parse_descriptor_file (filename);
    info_msg ("Descriptor: afu descriptor successfully initialized");
}

void
Descriptor::parse_descriptor_file (string filename)
{
    ifstream file (filename.c_str ());

    if (!file.is_open ())
        error_msg
        ("Descriptor::parse_descriptor_file: failed to open file %s",
         filename.c_str ());
    string line, field, colon, s_value, s_data;

    while (getline (file, line)) {
        // skip comments and empty lines
        if (line[0] == '#' || line == "")
            continue;
        stringstream ss (line);

        ss >> field >> colon >> s_value;

        uint64_t value, data;

        // Test for data values
        if (field == "data") {
            if (s_value.substr (0, 2) == "0x")
                s_value.erase(0, 2);
            getline (file, s_data);
            if (s_data.substr (0, 2) == "0x")
                s_data.erase(0, 2);
            value = strtoull(s_value.c_str(), NULL, 16);
            data = strtoull(s_data.c_str(), NULL, 16);
            info_msg ("Descriptor: setting offset 0x%x with value 0x%016llx",
                      value, data);
            uint64_t offset = to_vector_index(value);
            while (offset >= regs.size())
                regs.push_back(0);
            regs[offset] = data;
            continue;
        }

        // re-output s_value as unsigned int

        if (s_value.substr (0, 2) == "0x") {
            stringstream temp (s_value.substr (2));
            temp >> std::hex >> value;
            info_msg ("Descriptor: setting %s with value 0x%x", field.c_str (),
                      value);
        }
        else {
            stringstream temp (s_value);
            temp >> value;
            info_msg ("Descriptor: setting %s with value %d", field.c_str (),
                      value);
        }

        // set reg values base of the field name
        // reg0x00
        if (field == "num_ints_per_process")
            regs[to_vector_index (0x00)] =
                (regs[to_vector_index (0x00)] & 0x0000FFFFFFFFFFFF) |
                ((value & 0xFFFF) << 48);
        else if (field == "num_of_processes")
            regs[to_vector_index (0x00)] =
                (regs[to_vector_index (0x00)] & 0xFFFF0000FFFFFFFF) |
                ((value & 0xFFFF) << 32);
        else if (field == "num_of_afu_CRs")
            regs[to_vector_index (0x00)] =
                (regs[to_vector_index (0x00)] & 0xFFFFFFFF0000FFFF) |
                ((value & 0xFFFF) << 16);
        else if (field == "reg_prog_model")
            regs[to_vector_index (0x00)] =
                (regs[to_vector_index (0x00)] & 0xFFFFFFFFFFFF0000) |
                (value & 0xFFFF);
        // reg0x20
        else if (field == "AFU_CR_len")
            regs[to_vector_index (0x20)] =
                (regs[to_vector_index (0x20)] & 0xFF00000000000000) |
                (value & 0xFFFFFFFFFFFFFF);
        // reg0x28
        else if (field == "AFU_CR_offset")
            regs[to_vector_index (0x28)] = value;
        // reg0x30
        else if (field == "PerProcessPSA_control")
            regs[to_vector_index (0x30)] =
                (regs[to_vector_index (0x30)] & 0x00FFFFFFFFFFFFFF) |
                ((value & 0xFF) << 56);
        else if (field == "PerProcessPSA_length")
            regs[to_vector_index (0x30)] =
                (regs[to_vector_index (0x30)] & 0xFF00000000000000) |
                (value & 0xFFFFFFFFFFFFFF);
        // reg0x38
        else if (field == "PerProcessPSA_offset")
            regs[to_vector_index (0x38)] = value;
        // reg0x40
        else if (field == "AFU_EB_len")
            regs[to_vector_index (0x40)] = value & 0xFFFFFFFFFFFFFF;
        // reg0x48
        else if (field == "AFU_EB_offset")
            regs[to_vector_index (0x48)] = value;
        else
            warn_msg ("Field %s is currently not supported", field.c_str ());
    }
}

uint32_t Descriptor::to_vector_index (uint32_t byte_address) const
{
    return byte_address >> 3;
}

uint64_t
Descriptor::get_reg (uint32_t word_address, uint32_t mmio_double) const
{
    uint64_t
    data = regs[to_vector_index (word_address << 2)];

    if (mmio_double)
        return
            data;

    if (word_address & 0x1)
        return (data & 0xFFFFFFFF) | ((data & 0xFFFFFFFF) << 32);
    else
        return (data & 0xFFFFFFFF00000000LL) | (data >> 32);
}

bool
Descriptor::is_dedicated () const
{
    return ((get_reg_prog_model () & MASK_IS_DEDICATED) == MASK_IS_DEDICATED);
}

bool
Descriptor::is_directed () const
{
    return ((get_reg_prog_model () == MASK_IS_DIRECTED) == MASK_IS_DIRECTED);
}

// reg0x00
uint16_t
Descriptor::get_num_ints_per_process () const
{
    return (uint16_t) ((regs[to_vector_index (0x00)] >> 48) & 0xFFFF);
}

uint16_t
Descriptor::get_num_of_process () const
{
    return (uint16_t) ((regs[to_vector_index (0x00)] >> 32) & 0xFFFF);
}

uint16_t
Descriptor::get_num_of_afu_CRs () const
{
    return (uint16_t) ((regs[to_vector_index (0x00)] >> 16) & 0xFFFF);
}

uint16_t
Descriptor::get_reg_prog_model () const
{
    return (uint16_t) (regs[to_vector_index (0x00)] & 0xFFFF);
}

// reg0x20
uint64_t
Descriptor::get_AFU_CR_len () const
{
    return regs[to_vector_index (0x20)] & 0xFFFFFFFFFFFFFF;
}

// reg0x28
uint64_t
Descriptor::get_AFU_CR_offset () const
{
    return regs[to_vector_index (0x28)];
}

// reg0x30
uint8_t
Descriptor::get_PerProcessPSA_control () const
{
    return (uint8_t) ((regs[to_vector_index (0x30)] >> 56) & 0xFF);
}

uint64_t
Descriptor::get_PerProcessPSA_length () const
{
    return regs[to_vector_index (0x30)] & 0xFFFFFFFFFFFFFF;
}

// reg0x38
uint64_t
Descriptor::get_PerProcessPSA_offset () const
{
    return regs[to_vector_index (0x38)];
}

// reg0x40
uint64_t
Descriptor::get_AFU_EB_len () const
{
    return regs[to_vector_index (0x40)] & 0xFFFFFFFFFFFFFF;
}

// reg0x48
uint64_t
Descriptor::get_AFU_EB_offset () const
{
    return regs[to_vector_index (0x48)];
}
