/*
 * Copyright 2014 International Business Machines
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

#ifndef __psl_interface_t_h__
#define __psl_interface_t_h__ 1

#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

#define PSL_BUFFER_SIZE 200
#define PROTOCOL_PRIMARY 0
#define PROTOCOL_SECONDARY 9908
#define PROTOCOL_TERTIARY 0


/* Return codes for interface functions */

#define PSL_SUCCESS 0
#define PSL_DOUBLE_COMMAND 1			/* A command has been issued
						   before the preceeding
						   command of the same type has
						   been acknowledged */
#define PSL_MMIO_ACK_NOT_VALID 4		/* Read data from previos MMIO
						   read is not available */
#define PSL_BUFFER_READ_DATA_NOT_VALID 8	/* Read data from previous
						   buffer read is not
						   available */
#define PSL_COMMAND_NOT_VALID 32		/* There is no PSL command
						   available */
#define PSL_BAD_SOCKET 16			/* The socket connection could
						   not be established */
#define PSL_TRANSMISSION_ERROR 64		/* There was an error sending
						   data across the socket
						   interface */
#define PSL_CLOSE_ERROR 128			/* There was an error closing
						   the socket */
#define PSL_AUX2_NOT_VALID 256			/* There auxilliary signals
						   have not changed */

/* Job Control Codes */

#define PSL_JOB_START 0x90
#define PSL_JOB_RESET 0x80
#define PSL_JOB_LOAD 0x16
#define PSL_JOB_SAVE 0xC
#define PSL_JOB_STOP 0x60
#define PSL_JOB_LLCMD 0x45
#define PSL_JOB_SNOOP_SI 0x1
#define PSL_JOB_SNOOP_MI 0x3
#define PSL_JOB_SNOOP_MS 0x2
#define PSL_JOB_TIMEBASE 0x42

/* Response codes for PSL responses */

#define PSL_RESPONSE_DONE 0
#define PSL_RESPONSE_AERROR 1
#define PSL_RESPONSE_DERROR 3
#define PSL_RESPONSE_NLOCK 4
#define PSL_RESPONSE_NRES 5
#define PSL_RESPONSE_FLUSHED 6
#define PSL_RESPONSE_FAULT 7
#define PSL_RESPONSE_FAILED 8
#define PSL_RESPONSE_PAGED 10
#define PSL_RESPONSE_CONTEXT 11

/* Command codes for AFU commands */

#define PSL_COMMAND_READ_CL_NA   0x0A00
#define PSL_COMMAND_READ_CL_S    0x0A50
#define PSL_COMMAND_READ_CL_M    0x0A60
#define PSL_COMMAND_READ_CL_LCK  0x0A6B
#define PSL_COMMAND_READ_CL_RES  0x0A67
#define PSL_COMMAND_READ_PE      0x0A52
#define PSL_COMMAND_READ_PNA     0x0E00
#define PSL_COMMAND_READ_LS      0x0A90
#define PSL_COMMAND_READ_LM      0x0AA0
#define PSL_COMMAND_RD_GO_S      0x0AD0
#define PSL_COMMAND_RD_GO_M      0x0AF0
#define PSL_COMMAND_RWITM        0x0AE0
#define PSL_COMMAND_TOUCH_I      0x0240
#define PSL_COMMAND_TOUCH_S      0x0250
#define PSL_COMMAND_TOUCH_M      0x0260
#define PSL_COMMAND_TOUCH_LS     0x0290
#define PSL_COMMAND_TOUCH_LM     0x02A0
#define PSL_COMMAND_WRITE_MI     0x0D60
#define PSL_COMMAND_WRITE_MS     0x0D70

#define PSL_COMMAND_WRITE_UNLOCK 0x0D6B
#define PSL_COMMAND_WRITE_C      0x0D67
#define PSL_COMMAND_WRITE_NA     0x0D00
#define PSL_COMMAND_WRITE_INJ    0x0D10
#define PSL_COMMAND_WRITE_LM     0x0DA0
#define PSL_COMMAND_PUSH_I       0x0140
#define PSL_COMMAND_PUSH_S       0x0150
#define PSL_COMMAND_INVALIDATE   0x02C0
#define PSL_COMMAND_CASTOUT_I    0x09C0
#define PSL_COMMAND_CASTOUT_S    0x09D0
#define PSL_COMMAND_CLAIM_M      0x02E0
#define PSL_COMMAND_CLAIM_U      0x02F0
#define PSL_COMMAND_CLEAN        0x0210
#define PSL_COMMAND_FLUSH        0x0200
#define PSL_COMMAND_FLUSH_LCK    0x0248
#define PSL_COMMAND_ZERO_M       0x1160
#define PSL_COMMAND_INTREQ       0x0000
#define PSL_COMMAND_UNLOCK       0x027B
#define PSL_COMMAND_RESTART      0x0001

/* Create one of these structures to interface to an AFU model and use the functions below to manipulate it */

/* *INDENT-OFF* */
struct AFU_EVENT {
  int sockfd;                         /* socket file descriptor */
  uint32_t proto_primary;             /* socket protocol version 1st number */
  uint32_t proto_secondary;           /* socket protocol version 2nd number */
  uint32_t proto_tertiary;            /* socket protocol version 3rd number */
  int clock;                          /* clock */
  unsigned char tbuf[PSL_BUFFER_SIZE];/* transmit buffer for socket communications */
  unsigned char rbuf[PSL_BUFFER_SIZE];/* receive buffer for socket communications */
  uint32_t rbp;                       /* receive buffer position */
  uint64_t job_address;               /* effective address of the work element descriptor */
  uint64_t job_error;                 /* error code for completed job */
  uint32_t job_valid;                 /* AFU event contains a valid job control command */
  uint32_t job_code;                  /* job control command code as documented in the PSL workbook */
  uint32_t job_running;               /* a job is running in the accelerator */
  uint32_t job_done;                  /* a job has completed in the accelerator */
  uint32_t job_cack_llcmd;            /* LLCMD command has been processed by AFU */
  uint32_t job_code_parity;           /* Odd parity for ha_jcom (job_code) valid with ha_jval (job_valid) */
  uint32_t job_address_parity;        /* Odd parity for ha_jea (job_address) valid with ha_jval (job_valid) */
  uint32_t job_yield;                 /* Used to save context in Shared mode. */
  uint32_t timebase_request;          /* Requests PSL to send a timebase control command with current timebase value. */
  uint32_t parity_enable;             /* If asserted, AFU supports parity generation on various interface buses. */
  uint32_t mmio_address;              /* word address of the MMIO data to read/write */
  uint32_t mmio_address_parity;       /* Odd parity for MMIO address */
  uint64_t mmio_wdata;                /* write data for MMIO writes, unused if mmio_read is true */
  uint64_t mmio_wdata_parity;         /* Odd parity for MMIO write data */
  uint64_t mmio_rdata;                /* read data for MMIO reads */
  uint64_t mmio_rdata_parity;         /* Odd parity for MMIO read data */
  uint32_t mmio_valid;                /* AFU event contains a valid MMIO command */
  uint32_t mmio_read;                 /* MMIO command is a read type (otherwise it is a write type) */
  uint32_t mmio_double;               /* MMIO command is a 64-bit operation (otherwise read and write data should be limited to 32 bits) */
  uint32_t mmio_ack;                  /* MMIO command has been acknowledged */
  uint32_t mmio_afudescaccess;        /* MMIO command is access to AFU descriptor space */
  uint32_t response_valid;            /* AFU event contains a valid PSL response */
  uint32_t response_tag;              /* tag value from the command in the PSL_EVENT that is being responded to */
  uint32_t response_code;             /* response code for the command with tag value above as documented in the PSL workbook */
  int32_t credits;                    /* number of credits (positive or negative) to return to the AFU */
  uint32_t cache_state;               /* cache state granted to the AFU as documented in the PSL workbook */
  uint32_t cache_position;            /* The cache position assigned by PSL */
  uint32_t response_tag_parity;       /* Odd parity for ha_rtag valid with ha_rvalid */
  uint32_t buffer_read;               /* AFU event contains a valid buffer read request */
  uint32_t buffer_read_tag;           /* tag from command in PSL_EVENT which requested the buffer read */
  uint32_t buffer_read_tag_parity;    /* Odd parity for buffer read tag */
  uint32_t buffer_read_address;       /* address within the transfer of the 64 byte chunk of data to read */
  uint32_t buffer_read_length;        /* length of transfer, must be either 64 or 128 bytes */
  uint32_t buffer_read_latency;       /* Read buffer latency in clocks */
  uint32_t buffer_write;              /* AFU event contains a valid buffer write request */
  uint32_t buffer_write_tag;          /* tag from command in PSL_EVENT which requested the buffer write */
  uint32_t buffer_write_tag_parity;   /* Odd parity for buffer write tag */
  uint32_t buffer_write_address;      /* address within the transfer of the 64 byte chunk of data to write */
  uint32_t buffer_write_length;       /* length of transfer, must be either 64 or 128 bytes */
  unsigned char buffer_wdata[128];    /* 128B data to write to the AFUs buffer (only first half used for 64B calls) */
  unsigned char buffer_wparity[2];    /* 128b parity for the write data (only first half used for 64B calls) */
  uint32_t buffer_rdata_valid;        /* buffer read data is valid */
  unsigned char buffer_rdata[128];    /* 128B data to read from the AFUs buffer (only first half used for 64B calls) */
  unsigned char buffer_rparity[2];    /* 128b parity for the read data (only first half used for 64B calls) */
  uint32_t aux1_change;               /* The value of one of the auxilliary signals has changed (room) */
  uint32_t room;                      /* the number of commands PSL has room to accept */
  uint64_t command_address;           /* effective address for commands requiring an address */
  uint64_t command_address_parity;    /* Odd parity for effective address for command */
  uint32_t command_valid;             /* AFU event contains a valid command */
  uint32_t command_tag;               /* tag associated with the command. used for buffer allocation and response matching */
  uint32_t command_tag_parity;        /* Odd parity for command tag */
  uint32_t command_code;              /* command code as documented in the PSL workbook */
  uint32_t command_code_parity;       /* Odd parity for command code */
  uint32_t command_size;              /* number of bytes for commands requiring transfer size */
  uint32_t command_abort;             /* indicates that the command may be aborted */
  uint32_t command_handle;            /* Context handle (Process Element ID) */
  uint32_t aux2_change;               /* The value of one of the auxilliary signals has changed (running, job done or error, read latency) */
};
/* *INDENT-ON* */

#endif
