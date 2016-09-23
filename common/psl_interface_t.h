/*
 * Copyright 2014,2016 International Business Machines
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

// Choose ONE to define what PSL support level will be
#define PSL8 1
//#define PSL9lite 1
//#define PSL9 1

#define PSL_BUFFER_SIZE 200
#ifdef PSL8
#define PROTOCOL_PRIMARY 0
#define PROTOCOL_SECONDARY 9908
#define PROTOCOL_TERTIARY 1
#endif /* PSL8 */
#ifdef PSL9lite
#define PROTOCOL_PRIMARY 1
#define PROTOCOL_SECONDARY 0000
#define PROTOCOL_TERTIARY 0
#endif /* PSL9lite */
#ifdef PSL9
#define PROTOCOL_PRIMARY 2
#define PROTOCOL_SECONDARY 0000
#define PROTOCOL_TERTIARY 0
#endif /* PSL9 */

/* Select # of DMA interfaces, per config options in CH 17 of workbook */
#ifdef PSL9
#define PSL_DMA_A_SUPPORT 1
#define PSL_DMA_B_SUPPORT 0
#define MAX_DMA0_RD_CREDITS 8
#define MAX_DMA0_WR_CREDITS 8
#endif /* ifdef PSL9 config for DMA ports */

/* Return codes for interface functions */

#define PSL_SUCCESS 0
#define PSL_DOUBLE_COMMAND 1	/* A command has been issued
				   before the preceeding
				   command of the same type has
				   been acknowledged */
#ifdef PSL9
#define PSL_DOUBLE_DMA0_REQ 2
#endif

#define PSL_MMIO_ACK_NOT_VALID 4	/* Read data from previos MMIO
					   read is not available */
#define PSL_BUFFER_READ_DATA_NOT_VALID 8	/* Read data from previous
						   buffer read is not
						   available */
#define PSL_COMMAND_NOT_VALID 32	/* There is no PSL command
					   available */
#define PSL_BAD_SOCKET 16	/* The socket connection could
				   not be established */
#define PSL_VERSION_ERROR 48	/* The PSL versions in use on local & remote do not match */
#define PSL_TRANSMISSION_ERROR 64	/* There was an error sending
					   data across the socket
					   interface */
#define PSL_CLOSE_ERROR 128	/* There was an error closing
				   the socket */
#define PSL_AUX2_NOT_VALID 256	/* There auxilliary signals
				   have not changed */

/* Job Control Codes */

#define PSL_JOB_START 0x90
#define PSL_JOB_RESET 0x80
#define PSL_JOB_LLCMD 0x45
#define PSL_JOB_TIMEBASE 0x42

/* LLCMD decode */

#define PSL_LLCMD_MASK 0xFFFF000000000000LL
#define PSL_LLCMD_TERMINATE 0x0001000000000000LL
#define PSL_LLCMD_REMOVE 0x0002000000000000LL
#define PSL_LLCMD_ADD 0x0005000000000000LL
#define PSL_LLCMD_CONTEXT_MASK 0x000000000000FFFFLL

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
//#ifdef PSL9  /* new response codes for CAIA2 */
#if defined  PSL9 || defined PSL9lite  /* new response codes for CAIA2 */
#define PSL_RESPONSE_COMP_EQ 12
#define PSL_RESPONSE_COMP_NEQ 13
#define PSL_RESPONSE_CAS_INV 14
#endif /*#ifdef PSL9 new response codes for CAIA2 */

/* Command codes for AFU commands */

#define PSL_COMMAND_READ_CL_NA   0x0A00
#define PSL_COMMAND_READ_CL_S    0x0A50
#define PSL_COMMAND_READ_CL_M    0x0A60
#define PSL_COMMAND_READ_CL_LCK  0x0A6B
#define PSL_COMMAND_READ_CL_RES  0x0A67
#define PSL_COMMAND_READ_PE      0x0A52
#define PSL_COMMAND_READ_PNA     0x0E00
#define PSL_COMMAND_TOUCH_I      0x0240
#define PSL_COMMAND_TOUCH_S      0x0250
#define PSL_COMMAND_TOUCH_M      0x0260
#define PSL_COMMAND_WRITE_MI     0x0D60
#define PSL_COMMAND_WRITE_MS     0x0D70
#define PSL_COMMAND_WRITE_UNLOCK 0x0D6B
#define PSL_COMMAND_WRITE_C      0x0D67
#define PSL_COMMAND_WRITE_NA     0x0D00
#define PSL_COMMAND_WRITE_INJ    0x0D10
#define PSL_COMMAND_PUSH_I       0x0140
#define PSL_COMMAND_PUSH_S       0x0150
#define PSL_COMMAND_EVICT_I      0x1140
#define PSL_COMMAND_FLUSH        0x0100
#define PSL_COMMAND_INTREQ       0x0000
#define PSL_COMMAND_LOCK         0x016B
#define PSL_COMMAND_UNLOCK       0x017B
#define PSL_COMMAND_RESTART      0x0001
//not a psl9 cmd, but wasn't in 9908
#define PSL_COMMAND_ZERO_M	 0x1260
// add new CAIA2 commands
//#ifdef PSL9
#if defined  PSL9 || defined PSL9lite  /* new commands for CAIA2 */
#define PSL_COMMAND_CAS_E_4B	 0x0180
#define PSL_COMMAND_CAS_NE_4B	 0x0181
#define PSL_COMMAND_CAS_U_4B	 0x0182
#define PSL_COMMAND_CAS_E_8B	 0x0183
#define PSL_COMMAND_CAS_NE_8B	 0x0184
#define PSL_COMMAND_CAS_U_8B	 0x0185
#define PSL_COMMAND_ASBNOT	 0x0103
#define PSL_COMMAND_ARMW_CAS_T	 0x1000
#define PSL_COMMAND_ARMW_ADD	 0x1001
#define PSL_COMMAND_ARMW_AND	 0x1002
#define PSL_COMMAND_ARMW_XOR	 0x1003
#define PSL_COMMAND_ARMW_OR	 0x1004
#define PSL_COMMAND_ARMW_CAS_MAX_U	 0x1005
#define PSL_COMMAND_ARMW_CAS_MAX_S	 0x1006
#define PSL_COMMAND_ARMW_CAS_MIN_U	 0x1007
#define PSL_COMMAND_ARMW_CAS_MIN_S	 0x1008
#endif /* ifdef PSL9 add new commands for CAIA2 */
#ifdef PSL9 /* new DMA related commands */
#define PSL_COMMAND_XLAT_RD_P0	 0x1F00
#define PSL_COMMAND_XLAT_WR_P0	 0x1F01
#define PSL_COMMAND_XLAT_RD_P1	 0x1F08
#define PSL_COMMAND_XLAT_WR_P1	 0x1F09
#define PSL_COMMAND_ITAG_ABRT_RD 0x1F02
#define PSL_COMMAND_ITAG_ABRT_WR 0x1F03
#define PSL_COMMAND_XLAT_RD_TOUCH 0x1F10
#define PSL_COMMAND_XLAT_WR_TOUCH 0x1F11
#endif /* ifdef PSL9 add new commands for CAIA2 */


#ifdef PSL9  /* new DMA transaction type, sent status & completion status codes UPDATED to 9/14/16 spec  */
#define DMA_DTYPE_RD_REQ	0x0
#define DMA_DTYPE_WR_REQ_128	0x1
#define DMA_DTYPE_WR_REQ_MORE	0x2
#define DMA_DTYPE_ATOMIC	0x3

#define DMA_SENT_UTAG_STS_RD	0x0
#define DMA_SENT_UTAG_STS_WR	0x1
#define DMA_SENT_UTAG_STS_FAIL	0x2
#define DMA_SENT_UTAG_STS_FLUSH	0x3

#define DMA_CPL_TYPE_RD_128	0x0
#define DMA_CPL_TYPE_RD_PLUS	0x1
#define DMA_CPL_TYPE_ERR	0x2
#define DMA_CPL_TYPE_POISON_B	0x3
#define DMA_CPL_TYPE_ATOMIC_RSP	0x4
#endif /* new DMA type & status defs */


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
  #ifdef PSL9 /* add new PSL response interface signals for CAIA2 */
  uint32_t response_dma0_itag;        /* DMA translation tag for xlat_ *requests */
  uint32_t response_dma0_itag_parity; /* DMA translation tag parity   */
  uint32_t response_extra;            /* extra response information received from xlate logic */
  uint32_t response_r_pgsize;         /* command translated page size. values defined in CAIA2 workbook */
  #endif /* ifdef PSL9 */
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
//#ifdef PSL9 /* new cmd int signals for CAIA2 */
#if defined  PSL9 || defined PSL9lite  /* new cmd int signals for CAIA2 */
  uint32_t command_cpagesize;	      /*  Page size hint used by PSL for predicting page size during ERAT lookup & paged xlation ordering..codes documented in PSL workbook tbl 1-1 */
#endif /* new cmd int signals  */
#ifdef PSL9 /* new dma0 interface signals for CAIA2 UPDATED for 9/14/16 spec */
  uint32_t dma0_dvalid;     	      /* DMA request from AFU is valid */
  uint32_t dma0_req_utag;	      /* DMA transaction request user transaction tag */
  uint32_t dma0_req_itag;     	      /* DMA transaction request user translation identifier */
  uint32_t dma0_req_type;	      /* DMA transaction request transaction type.  */
  uint32_t dma0_req_size;	      /* DMA transaction request transaction size in bytes */
  uint32_t atomic_op;		      /* Transaction request attribute - Atomic opcode */
  //unsigned char dma0_req_data[128];	      /* DMA data alignment is First byte first */
  uint32_t dma0_sent_utag_valid;      /* DMA request sent by PSL */
  uint32_t dma0_sent_utag;    	      /* DMA sent request indicates the UTAG of the request sent by PSL */
  uint32_t dma0_sent_utag_status;     /* DMA sent request indicates the status of the command that was sent by PSL. */
  uint32_t dma0_completion_valid;     /* DMA completion received  */
  uint32_t dma0_completion_utag;      /* DMA completion indicates the UTAG associated with the received completion data */
  uint32_t dma0_completion_type;      /* DMA completion indicates the type of response received with the current completion */
  uint32_t dma0_completion_size;      /* DMA completion indicates size of completion received */
  uint32_t dma0_completion_laddr;     /* DMA completion Atomic attribute - lower addr bits of rx cmpl */
  uint32_t dma0_completion_byte_count; /* DMA completion remaining amount of bytes required to complete originating read request
						including bytes being transferred in the current transaction   */
  unsigned char dma0_req_data[128];	      /* DMA data alignment is First byte first */
  unsigned char dma0_completion_data[128];  /* DMA completion data alignment is First Byte first */
#endif /* ifdef PSL9 */

};
/* *INDENT-ON* */

#endif
