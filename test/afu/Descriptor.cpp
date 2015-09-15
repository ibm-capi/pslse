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
 * Description: Descriptor.cpp
 *
 *  This file defines the Descriptor class for the test AFU.
 */

#include "Descriptor.h"

#include <string>
#include <stdint.h>
#include <fstream>
#include <sstream>

using std::string;
using std::ifstream;
using std::stringstream;

 Descriptor::Descriptor(string filename):regs(DESCRIPTOR_NUM_REGS)
{
	info_msg("Descriptor: attempting to set up descriptor with %s",
		 filename.c_str());
	parse_descriptor_file(filename);
	info_msg("Descriptor: afu descriptor successfully initialized");
}

void Descriptor::parse_descriptor_file(string filename)
{
	ifstream file(filename.c_str());
	if (!file.is_open())
		error_msg
		    ("Descriptor::parse_descriptor_file: failed to open file %s",
		     filename.c_str());
	string line, field, colon, s_value;
	while (getline(file, line)) {
		// skip comments and empty lines
		if (line[0] == '#' || line == "")
			continue;
		stringstream ss(line);
		ss >> field >> colon >> s_value;

		// re-output s_value as unsigned int
		uint64_t value;
		if (s_value.substr(0, 2) == "0x") {
			stringstream temp(s_value.substr(2));
			temp >> std::hex >> value;
			info_msg("Descriptor: setting %s with value %x",
				 field.c_str(), value);
		} else {
			stringstream temp(s_value);
			temp >> value;
			info_msg("Descriptor: setting %s with value %d",
				 field.c_str(), value);
		}

		// set reg values base of the field name
		// reg0x00
		if (field == "num_ints_per_process")
			regs[to_vector_index(0x00)] =
			    (regs[to_vector_index(0x00)] & 0x0000FFFFFFFFFFFF) |
			    ((value & 0xFFFF) << 48);
		else if (field == "num_of_processes")
			regs[to_vector_index(0x00)] =
			    (regs[to_vector_index(0x00)] & 0xFFFF0000FFFFFFFF) |
			    ((value & 0xFFFF) << 32);
		else if (field == "num_of_afu_CRs")
			regs[to_vector_index(0x00)] =
			    (regs[to_vector_index(0x00)] & 0xFFFFFFFF0000FFFF) |
			    ((value & 0xFFFF) << 16);
		else if (field == "reg_prog_model")
			regs[to_vector_index(0x00)] =
			    (regs[to_vector_index(0x00)] & 0xFFFFFFFFFFFF0000) |
			    (value & 0xFFFF);
		// reg0x20
		else if (field == "AFU_CR_len")
			regs[to_vector_index(0x20)] =
			    (regs[to_vector_index(0x20)] & 0xFF00000000000000) |
			    (value & 0xFFFFFFFFFFFFFF);
		// reg0x28
		else if (field == "AFU_CR_offset")
			regs[to_vector_index(0x28)] = value;
		// reg0x30
		else if (field == "PerProcessPSA_control")
			regs[to_vector_index(0x30)] =
			    (regs[to_vector_index(0x30)] & 0x00FFFFFFFFFFFFFF) |
			    ((value & 0xFF) << 56);
		else if (field == "PerProcessPSA_length")
			regs[to_vector_index(0x30)] =
			    (regs[to_vector_index(0x30)] & 0xFF00000000000000) |
			    (value & 0xFFFFFFFFFFFFFF);
		// reg0x38
		else if (field == "PerProcessPSA_offset")
			regs[to_vector_index(0x38)] = value;
		// reg0x40
		else if (field == "AFU_EB_len")
			regs[to_vector_index(0x40)] = value & 0xFFFFFFFFFFFFFF;
		// reg0x48
		else if (field == "AFU_EB_offset")
			regs[to_vector_index(0x48)] = value;
		else
			warn_msg("Field %s is currently not supported",
				 field.c_str());
	}
}

uint32_t Descriptor::to_vector_index(uint32_t byte_address) const {
	return byte_address >> 3;
}

uint64_t Descriptor::get_reg(uint32_t word_address) const {
	return regs[to_vector_index(word_address << 2)];
}

// reg0x00 uint16_t Descriptor::get_num_ints_per_process() const {
//	return (uint16_t) ((regs[to_vector_index(0x00)] >> 48) & 0xFFFF);
//}

uint16_t Descriptor::get_num_of_process() const {
	return (uint16_t) ((regs[to_vector_index(0x00)] >> 32) & 0xFFFF);
}

uint16_t Descriptor::get_num_of_afu_CRs() const {
	return (uint16_t) ((regs[to_vector_index(0x00)] >> 16) & 0xFFFF);
}

uint16_t Descriptor::get_reg_prog_model() const {
	return (uint16_t) (regs[to_vector_index(0x00)] & 0xFFFF);
}

// reg0x20 uint64_t Descriptor::get_AFU_CR_len() const {
//	return regs[to_vector_index(0x20)] & 0xFFFFFFFFFFFFFF;
//}

// reg0x28 uint64_t Descriptor::get_AFU_CR_offset() const {
//	return regs[to_vector_index(0x28)];
//}

// reg0x30 uint8_t Descriptor::get_PerProcessPSA_control() const {
//	return (uint8_t) ((regs[to_vector_index(0x30)] >> 56) & 0xFF);
//}

uint64_t Descriptor::get_PerProcessPSA_length() const {
	return regs[to_vector_index(0x30)] & 0xFFFFFFFFFFFFFF;
}

// reg0x38 uint64_t Descriptor::get_PerProcessPSA_offset() const {
//	return regs[to_vector_index(0x38)];
//}

// reg0x40 uint64_t Descriptor::get_AFU_EB_len() const {
//	return regs[to_vector_index(0x40)] & 0xFFFFFFFFFFFFFF;
//}

// reg0x48 uint64_t Descriptor::get_AFU_EB_offset() const {
//	return regs[to_vector_index(0x48)];
//}
