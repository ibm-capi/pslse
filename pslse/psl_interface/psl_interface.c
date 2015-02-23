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

#include "psl_interface.h"

#include <arpa/inet.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

/* For PSL out-bound haX parity buses, generate Odd parity bit for a specified
 * data size set */

static uint32_t genoddParitybitperbytes(uint64_t data)
{
    //For odd parity: If sum of data bits is even, parity is 1
    uint32_t oddparity;
    oddparity = 1; //since odd, start off setting

    // Count off least significant asserted bit
    while (data)
    {
	oddparity=1-oddparity;	// 0->1 or 1->0
        data&=data-1;		// Remove lsb
    }

    return oddparity;
}

static void set_protocol_level (struct AFU_EVENT *event, uint32_t primary,
                                uint32_t secondary, uint32_t tertiary)
{
  if ((event->proto_primary != primary) ||
      (event->proto_secondary != secondary) ||
      (event->proto_tertiary != tertiary))
    {
      printf ("PSL_SOCKET:WARNING: Adjusting PSL interface protocol level!\n");
      printf ("PSL_SOCKET:\tPlease review changes betwen levels.\n");
      printf ("PSL_SOCKET:\tSupported PSL protocol level: %d.%d.%d\n",
	      event->proto_primary, event->proto_secondary,
	      event->proto_tertiary);
    }
  event->proto_primary = primary;
  event->proto_secondary = secondary;
  event->proto_tertiary = tertiary;
}

static int establish_protocol (struct AFU_EVENT *event)
{
  int bc, bl, bp, i;
  bp = 0;
  bl = 16;
  fd_set watchset;		/* fds to read from */
  uint8_t byte;
  uint32_t primary, secondary, tertiary;

  // Send protocol ID to other side of socket connection
  event->tbuf[0] = 'P';
  event->tbuf[1] = 'S';
  event->tbuf[2] = 'L';
  event->tbuf[3] = '\0';
  for (i = 0; i < 4; i++)
    {
      event->tbuf[4+i] = ((event->proto_primary) >> ((3 - i) * 8)) & 0xFF;
    }
  for (i = 0; i < 4; i++)
    {
      event->tbuf[8+i] = ((event->proto_secondary) >> ((3 - i) * 8)) & 0xFF;
    }
  for (i = 0; i < 4; i++)
    {
      event->tbuf[12+i] = ((event->proto_tertiary) >> ((3 - i) * 8)) & 0xFF;
    }
  while (bp < bl)
    {
      bc = send (event->sockfd, event->tbuf + bp, bl - bp, 0);
      if (bc < 0)
	return PSL_TRANSMISSION_ERROR;
      bp += bc;
    }

  // Get protocol ID from other side of socket connection
  bc = 0;
  FD_ZERO (&watchset);
  FD_SET (event->sockfd, &watchset);
  select (event->sockfd + 1, &watchset, NULL, NULL, NULL);
  while ((event->rbp< 16) && (bc != -1))
    {
      if ((bc = recv (event->sockfd, &(event->rbuf[event->rbp]), 1, 0)) == -1)
	{
	  if (errno == EWOULDBLOCK)
	    {
              select (event->sockfd + 1, &watchset, NULL, NULL, NULL);
	      continue;
	    }
	  else
	    {
	      return PSL_BAD_SOCKET;
	    }
	}
      event->rbp += bc;
    }
  event->rbp = 0;

  if (strcmp((char *) event->rbuf, "PSL"))
    return PSL_BAD_SOCKET;

  primary = 0;
  for (i = 4; i<8; i++)
    {
      byte = event->rbuf[i];
      primary <<= 8;
      primary += (uint32_t) byte;
    }

  secondary = 0;
  for (i = 8; i<12; i++)
    {
      byte = event->rbuf[i];
      secondary <<= 8;
      secondary += (uint32_t) byte;
    }

  tertiary = 0;
  for (i = 12; i<16; i++)
    {
      byte = event->rbuf[i];
      tertiary <<= 8;
      tertiary += (uint32_t) byte;
    }

  // Test if other side with adjust protocol level down
  if (primary > event->proto_primary)
    return PSL_SUCCESS;
  if (secondary > event->proto_secondary)
    return PSL_SUCCESS;
  if (tertiary > event->proto_tertiary)
    return PSL_SUCCESS;

  // Adjust protocol level down on this side if neccesary
  if (primary < event->proto_primary)
    set_protocol_level (event, primary, secondary, tertiary);
  else if (secondary < event->proto_secondary)
    set_protocol_level (event, primary, secondary, tertiary);
  else if (tertiary < event->proto_tertiary)
    set_protocol_level (event, primary, secondary, tertiary);

  return PSL_SUCCESS;
}

/* Call this at startup to reset all the event indicators */

void
psl_event_reset (struct AFU_EVENT *event)
{
  memset(event, 0, sizeof(*event));
  event->proto_primary = PROTOCOL_PRIMARY;
  event->proto_secondary = PROTOCOL_SECONDARY;
  event->proto_tertiary = PROTOCOL_TERTIARY;
}

/* Call this once after creation to initialize the AFU_EVENT structure and
 * open a socket conection to an AFU server.  This function initializes the
 * PSL side of the interface which is the client in the socket connection
 * server_host should be the name of the server hosting the simulation of
 * the AFU and port is the active port on that server. */

int
psl_init_afu_event (struct AFU_EVENT *event, char *server_host, int port)
{
  psl_event_reset (event);
  event->room = 64;
  event->rbp = 0;
  struct hostent *he;
  if ((he = gethostbyname (server_host)) == NULL)
    {
      herror("gethostbyname");
      return PSL_BAD_SOCKET;
    }
  struct sockaddr_in ssadr;
  memset (&ssadr, 0, sizeof (ssadr));
  memcpy (&ssadr.sin_addr, he->h_addr_list[0], he->h_length);
  ssadr.sin_family = AF_INET;
  ssadr.sin_port = htons (port);
  event->sockfd = socket (PF_INET, SOCK_STREAM, 0);
  if (event->sockfd == 0)
    {
      perror("socket");
      return PSL_BAD_SOCKET;
    }
  if (connect (event->sockfd, (struct sockaddr *) &ssadr, sizeof (ssadr)) < 0)
    {
      perror("connect");
      return PSL_BAD_SOCKET;
    }
  fcntl (event->sockfd, F_SETFL, O_NONBLOCK);

  int rc = establish_protocol (event);
  printf ("PSL_SOCKET: Using PSL protocol level : %d.%d.%d\n",
	  event->proto_primary, event->proto_secondary, event->proto_tertiary);

  return rc;
}

/* Call this to close the socket connection from either side */

int
psl_close_afu_event (struct AFU_EVENT *event)
{
  if (close (event->sockfd))
    {
      return PSL_CLOSE_ERROR;
    }
  else
    {
      return PSL_SUCCESS;
    }
}

/* Call this once after creation to initialize the AFU_EVENT structure. */
/* This function initializes the AFU side of the interface which is the
 * server in the socket connection. */

int
psl_serv_afu_event (struct AFU_EVENT *event, int port)
{
  int cs = 0;
  psl_event_reset (event);
  event->room = 64;
  event->rbp = 0;
  struct sockaddr_in ssadr, csadr;
  unsigned int csalen = sizeof (csadr);
  memset (&ssadr, 0, sizeof (ssadr));
  ssadr.sin_family = AF_UNSPEC;
  ssadr.sin_addr.s_addr = INADDR_ANY;
  ssadr.sin_port = htons (port);
  event->sockfd = socket (PF_INET, SOCK_STREAM, 0);
  if (event->sockfd < 0)
    {
      return PSL_BAD_SOCKET;
    }
  if (bind (event->sockfd, (struct sockaddr *) &ssadr, sizeof (ssadr)) == -1)
    {
      close (event->sockfd);
      return PSL_BAD_SOCKET;
    }
  char hostname[1024];
  hostname[1023] = '\0';
  gethostname(hostname, 1023);
  printf ("AFU Server is waiting for connection on %s:%d\n", hostname, port);
  fflush (stdout);
  if (listen (event->sockfd, 10) == -1)
    {
      close (event->sockfd);
      return PSL_BAD_SOCKET;
    }
  cs = accept (event->sockfd, (struct sockaddr *) &csadr, &csalen);
  close (event->sockfd);
  if (cs < 0)
    {
      return PSL_BAD_SOCKET;
    }
  event->sockfd = cs;
  fcntl (event->sockfd, F_SETFL, O_NONBLOCK);
  char clientname[1024];
  clientname[1023] = '\0';
  getnameinfo((struct sockaddr *) &csadr, sizeof(csadr), clientname, 1024, NULL, 0, 0);
  printf ("PSL client connection from %s\n", clientname);

  int rc = establish_protocol (event);
  printf ("Using PSL protocol level : %d.%d.%d\n", event->proto_primary,
	  event->proto_secondary, event->proto_tertiary);

  return rc;
}

/* Call this to change auxilliary signals (room) */

int
psl_aux1_change (struct AFU_EVENT *event, uint32_t room)
{
  if (event->aux1_change)
    {
      return PSL_DOUBLE_COMMAND;
    }
  else
    {
      event->aux1_change = 1;
      event->room = room;
      return PSL_SUCCESS;
    }
}

/* Call this to create an accelerator control command */

int
psl_job_control (struct AFU_EVENT *event, uint32_t job_code, uint64_t address)
{
  if (event->job_valid)
    {
      return PSL_DOUBLE_COMMAND;
    }
  else
    {
      event->job_valid = 1;
      event->job_code = job_code;
      event->job_address = address;
      event->job_code_parity = genoddParitybitperbytes((uint64_t) job_code);
      event->job_address_parity = genoddParitybitperbytes(address);
      return PSL_SUCCESS;
    }
}

/* Call this to create an MMIO read command. If the dbl argument is 1, 64 bits
 * are transferred.  If it is 0, 32 bits are transferred */

int
psl_mmio_read (struct AFU_EVENT *event,
	       uint32_t dbl,
	       uint32_t address,
	       uint32_t afudescaccess)
{
  if (event->mmio_valid)
    {
      return PSL_DOUBLE_COMMAND;
    }
  else
    {
      event->mmio_valid = 1;
      event->mmio_read = 1;
      event->mmio_double = dbl;
      event->mmio_address = address;
      event->mmio_address_parity = genoddParitybitperbytes(address);
      event->mmio_afudescaccess = afudescaccess;
      return PSL_SUCCESS;
    }
}

/* Call this to create an MMIO write command. If the dbl argument is 1, 64 bits
 * are transferred.  If it is 0, 32 bits are transferred (least significant
 * 32 bits of write_data. */

int
psl_mmio_write (struct AFU_EVENT *event,
		uint32_t dbl,
		uint32_t address,
		uint64_t write_data,
		uint32_t afudescaccess)
{
  if (event->mmio_valid)
    {
      return PSL_DOUBLE_COMMAND;
    }
  else
    {
      event->mmio_valid = 1;
      event->mmio_read = 0;
      event->mmio_double = dbl;
      event->mmio_address = address;
      event->mmio_address_parity = genoddParitybitperbytes(address);
      event->mmio_wdata = write_data;
      event->mmio_wdata_parity = genoddParitybitperbytes(write_data);
      event->mmio_afudescaccess = afudescaccess;
      return PSL_SUCCESS;
    }
}

/* Call this to create a command response */

int
psl_response (struct AFU_EVENT *event,
	      uint32_t tag,
	      uint32_t response_code,
	      int credits, uint32_t cache_state, uint32_t cache_position)
{
  (void) tag;
  if (event->response_valid)
    {
      return PSL_DOUBLE_COMMAND;
    }
  else
    {
      event->response_valid = 1;
      event->response_tag = tag;
      event->response_tag_parity = genoddParitybitperbytes(tag);
      event->response_code = response_code;
      event->credits = credits;
      event->cache_state = cache_state;
      event->cache_position = cache_position;
      return PSL_SUCCESS;
    }
}

/* Call this to read a buffer */
/* Length must be either 64 or 128 which is the transfer size in bytes.
 * For 64B transfers, only the first half of the array is used */

int
psl_buffer_read (struct AFU_EVENT *event,
		 uint32_t tag, uint64_t address, uint32_t length)
{
  if (event->buffer_read)
    {
      return PSL_DOUBLE_COMMAND;
    }
  else
    {
      event->buffer_read = 1;
      event->buffer_read_tag = tag;
      event->buffer_read_tag_parity = genoddParitybitperbytes(tag);
      event->buffer_read_address = address;
      event->buffer_read_length = length;
      return PSL_SUCCESS;
    }
}

/* Call this to write a buffer, write_data is a 32 element array of 32-bit
 * values, write_parity is a 4 element array of 32-bit values.
 * Length must be either 64 or 128 which is the transfer size in bytes.
 * For 64B transfers, only the first half of the array is used */

int
psl_buffer_write (struct AFU_EVENT *event,
		  uint32_t tag,
		  uint64_t address,
		  uint32_t length,
		  uint8_t * write_data, uint8_t * write_parity)
{
  if (event->buffer_write)
    {
      return PSL_DOUBLE_COMMAND;
    }
  else
    {
      event->buffer_write = 1;
      event->buffer_write_tag = tag;
      event->buffer_write_tag_parity = genoddParitybitperbytes(tag);
      event->buffer_write_address = address;
      event->buffer_write_length = length;
      memcpy (event->buffer_wdata, write_data, length);
      memcpy (event->buffer_wparity, write_parity, length / 64);
      return PSL_SUCCESS;
    }
}

/* Call after an event is received from the AFU to see if previous MMIO
 * operation has been acknowledged and extract read MMIO data if available. */

int
psl_get_mmio_acknowledge (struct AFU_EVENT *event,
			  uint64_t * read_data,
			  uint32_t * read_data_parity)
{
  if (!event->mmio_ack)
    {
      return PSL_MMIO_ACK_NOT_VALID;
    }
  else
    {
      event->mmio_ack = 0;
      event->mmio_valid = 0;
      *read_data = event->mmio_rdata;
      *read_data_parity = event->mmio_rdata_parity;
      return PSL_SUCCESS;
    }
}

/* Call after an event is received from the AFU to see if any of the auxilliary
 * signals have changed values */

int
psl_get_aux2_change (struct AFU_EVENT *event,
		     uint32_t * job_running,
		     uint32_t * job_done,
		     uint32_t * job_cack_llcmd,
		     uint64_t * job_error,
		     uint32_t * job_yield,
		     uint32_t * tb_request,
		     uint32_t * par_enable,
		     uint32_t * read_latency)
{
  if (!event->aux2_change)
    {
      return PSL_AUX2_NOT_VALID;
    }
  else
    {
      event->aux2_change = 0;
      *job_running = event->job_running;
      *job_done = event->job_done;
      *job_cack_llcmd = event->job_cack_llcmd;
      *job_error = event->job_error;
      *job_yield = event->job_yield;
      *tb_request = event->timebase_request;
      *par_enable = event->parity_enable;
      *read_latency = event->buffer_read_latency;
      return PSL_SUCCESS;
    }
}

/* Call after an event is received from the AFU to extract read buffer data if
 * available. read_data is a 32 element array of 32-bit values, read_parity is
 * a 4 element array of 32-bit values.
 * Note: fields in AFU_EVENT structre can also be accessed directly */

int
psl_get_buffer_read_data (struct AFU_EVENT *event,
			  uint8_t * read_data, uint8_t * read_parity)
{
  if (!event->buffer_rdata_valid)
    {
      return PSL_BUFFER_READ_DATA_NOT_VALID;
    }
  else
    {
      event->buffer_rdata_valid = 0;
      event->buffer_read = 0;
      memcpy (read_data, event->buffer_rdata, sizeof (event->buffer_rdata));
      memcpy (read_parity, event->buffer_rparity,
	      sizeof (event->buffer_rparity));
      return PSL_SUCCESS;
    }
}

/* Call after an event is received from the AFU to extract a PSL command
 * if available.
 * Note: fields in AFU_EVENT structre can also be accessed directly */

int
psl_get_command (struct AFU_EVENT *event,
		 uint32_t * command,
		 uint32_t * command_parity,
		 uint32_t * tag,
		 uint32_t * tag_parity,
		 uint64_t * address,
		 uint64_t * address_parity,
		 uint32_t * size,
		 uint32_t * abort,
		 uint32_t * handle)
{
  if (!event->command_valid)
    {
      return PSL_COMMAND_NOT_VALID;
    }
  else
    {
      event->command_valid = 0;
      *command = event->command_code;
      *command_parity = event->command_code_parity;
      *address = event->command_address;
      *address_parity = event->command_address_parity;
      *tag = event->command_tag;
      *tag_parity = event->command_tag_parity;
      *size = event->command_size;
      *abort = event->command_abort;
      *handle = event->command_handle;
      return PSL_SUCCESS;
    }
}

/* Call this to send an event to the AFU model after calling one or more of:
 * psl_aux1_change, psl_job_control, psl_mmio_read, psl_mmio_write,
 * psl_response, psl_buffer_read, psl_buffer_write */

int
psl_signal_afu_model (struct AFU_EVENT *event)
{
  int i, bc, bl;
  int bp = 1;
  if (event->clock != 0)
    return PSL_TRANSMISSION_ERROR;
  event->clock = 1;
  event->tbuf[0] = 0x40;
  if (event->aux1_change != 0)
    {
      event->tbuf[0] = event->tbuf[0] | 0x20;
      event->tbuf[bp++] = event->room;
      event->aux1_change = 0;
    }
  if (event->job_valid != 0)
    {
      event->tbuf[0] = event->tbuf[0] | 0x10;
      event->tbuf[bp++] = event->job_code;
      for (i = 0; i < 8; i++)
	{
	  event->tbuf[bp++] = ((event->job_address) >> ((7 - i) * 8)) & 0xFF;
	}
      event->tbuf[bp++] = (((event->job_address_parity) << 1) & 0x2) |
                          ((event->job_code_parity) & 0x1);
      event->job_valid = 0;
    }
  if (event->mmio_valid != 0)
    {
      event->tbuf[0] = event->tbuf[0] | 0x08;
      if (event->mmio_read != 0)
	{
	  event->tbuf[bp] = 0x01;
	}
      else
	{
	  event->tbuf[bp] = 0x00;
	}
      if (event->mmio_double != 0)
	{
	  event->tbuf[bp] = event->tbuf[bp] | 0x02;
	}
      if (event->mmio_afudescaccess != 0)
        {
	  event->tbuf[bp] = event->tbuf[bp] | 0x04;
        }
      if (event->mmio_address_parity != 0)
        {
	  event->tbuf[bp] = event->tbuf[bp] | 0x08;
        }
      if (event->mmio_wdata_parity != 0)
        {
	  event->tbuf[bp] = event->tbuf[bp] | 0x10;
        }
      bp++;
      for (i = 0; i < 3; i++)
	{
	  event->tbuf[bp++] = ((event->mmio_address) >> ((2 - i) * 8)) & 0xFF;
	}
      for (i = 0; i < 8; i++)
	{
	  event->tbuf[bp++] = ((event->mmio_wdata) >> ((7 - i) * 8)) & 0xFF;
	}
      event->mmio_valid = 0;
    }
  if (event->response_valid != 0)
    {
      event->tbuf[0] = event->tbuf[0] | 0x04;
      event->tbuf[bp++] = event->response_tag;
      event->tbuf[bp++] = event->response_tag_parity;
      event->tbuf[bp++] = event->response_code;
      event->tbuf[bp++] = ((event->cache_position) >> 5) & 0xFF;
      event->tbuf[bp++] = ((event->cache_position) << 3) |
                          (((event->cache_state) << 1) & 0x6) |
                          (((event->credits) >> 8) & 1);
      event->tbuf[bp++] = event->credits & 0xFF;
      event->response_valid = 0;
    }
  if (event->buffer_read != 0)
    {
      event->tbuf[0] = event->tbuf[0] | 0x02;
      event->tbuf[bp++] = event->buffer_read_tag;
      event->tbuf[bp++] = event->buffer_read_tag_parity;
      if (event->buffer_read_length > 64)
	{
	  event->tbuf[bp++] = 0x80 | (event->buffer_read_address & 0x3F);
	}
      else
	{
	  event->tbuf[bp++] = 0x00 | (event->buffer_read_address & 0x3F);
	}
      event->buffer_read = 0;
    }
  if (event->buffer_write != 0)
    {
      event->tbuf[0] = event->tbuf[0] | 0x01;
      event->tbuf[bp++] = event->buffer_write_tag;
      event->tbuf[bp++] = event->buffer_write_tag_parity;
      if (event->buffer_write_length > 64)
	{
	  event->tbuf[bp++] = 0x80 | (event->buffer_write_address & 0x3F);
	}
      else
	{
	  event->tbuf[bp++] = 0x00 | (event->buffer_write_address & 0x3F);
	}
      for (i = 0; i < 128; i++)
	{
	  event->tbuf[bp++] = event->buffer_wdata[i];
	}
      for (i = 0; i < 2; i++)
	{
          event->tbuf[bp++] = event->buffer_wparity[i];
	}
      event->buffer_write = 0;
    }
  bl = bp;
  bp = 0;
  while (bp < bl)
    {
      bc = send (event->sockfd, event->tbuf + bp, bl - bp, 0);
      if (bc < 0)
	return PSL_TRANSMISSION_ERROR;
      bp += bc;
    }
  return PSL_SUCCESS;
}

/* Call this to send an event to the PSL model */

int
psl_signal_psl_model (struct AFU_EVENT *event)
{
  int i, bc, bl;
  int bp = 1;
  if (event->clock != 1)
    return PSL_SUCCESS;
  event->clock = 0;
  event->tbuf[0] = 0x10;
  if (event->aux2_change)
    {
      event->tbuf[0] = event->tbuf[0] | 0x08;
      event->tbuf[bp++] = (((event->buffer_read_latency) << 4) & 0xF0) |
                          (((event->job_running) << 1) & 0x2) |
	                  (event->job_done & 1);
      for (i = 0; i < 8; i++)
	{
	  event->tbuf[bp++] = ((event->job_error) >> ((7 - i) * 8)) & 0xFF;
	}
      event->tbuf[bp++] = (((event->job_cack_llcmd) << 3) & 0x08) |
                          (((event->job_yield) << 2) & 0x04) |
                          (((event->timebase_request) << 1) & 0x03) |
                          ((event->parity_enable) & 0x01);
      event->aux2_change = 0;
    }
  if (event->mmio_ack)
    {
      event->tbuf[0] = event->tbuf[0] | 0x04;
      for (i = 0; i < 8; i++)
	{
	  event->tbuf[bp++] = ((event->mmio_rdata) >> ((7 - i) * 8)) & 0xFF;
	}
      event->tbuf[bp++] = event->mmio_rdata_parity;
      event->mmio_ack = 0;
    }
  if (event->buffer_rdata_valid)
    {
      event->tbuf[0] = event->tbuf[0] | 0x02;
      for (i = 0; i < 128; i++)
	{
	  event->tbuf[bp++] = event->buffer_rdata[i];
	}
      for (i = 0; i < 2; i++)
	{
	  event->tbuf[bp++] = event->buffer_rparity[i];
	}
      event->buffer_rdata_valid = 0;
    }
  if (event->command_valid)
    {
      event->tbuf[0] = event->tbuf[0] | 0x01;
      event->tbuf[bp++] = event->command_tag;
      event->tbuf[bp++] = (((event->command_abort) << 4) & 0x70) |
                          (((event->command_code) >> 8) & 0x0F);
      event->tbuf[bp++] = event->command_code & 0xFF;
      event->tbuf[bp++] = (((event->command_tag_parity) << 6) & 0x40) |
                          (((event->command_code_parity) << 5) & 0x20) |
                          (((event->command_address_parity) << 4) & 0x10) |
	                  (((event->command_size) >> 8) & 0x0F);
      event->tbuf[bp++] = event->command_size & 0xFF;
      for (i = 0; i < 8; i++)
	{
	  event->tbuf[bp++] =
	    ((event->command_address) >> ((7 - i) * 8)) & 0xFF;
	}
      for (i = 0; i < 2; i++)
	{
	  event->tbuf[bp++] =
	    ((event->command_handle) >> ((1 - i) * 8)) & 0xFF;
	}
      event->command_valid = 0;
    }

  bl = bp;
  bp = 0;
  while (bp < bl)
    {
      bc = send (event->sockfd, event->tbuf + bp, bl - bp, 0);
      if (bc < 0)
	return PSL_TRANSMISSION_ERROR;
      bp += bc;
    }
  return PSL_SUCCESS;
}

/* This function checks the socket connection for data from the external AFU
 * simulator. It needs to be called periodically to poll the socket connection.
 * It will update the AFU_EVENT structure.
 * It returns a 1 if there are new events to process, 0 if not, -1 on error or
 * close.  On a 1 return, the following functions should be called to retrieve
 * the individual event:
 * psl_get_command
 * psl_get_buffer_read_data
 * psl_get_mmio_acknowledge
 * A psl command can come at any time so that function should always be called
 * but buffer read data and MMIO acknowledges will only come as a result of
 * actions from the PSL simulation so if it is known that there are no
 * outstanding actions, these need not be called. The check in these functions
 * is very quick though so it also probably wouldn't hurt to always call them */

int
psl_get_afu_events (struct AFU_EVENT *event)
{
  int bc = 0;
  int rbc = 1;
  fd_set watchset;		/* fds to read from */
  /* initialize watchset */
  FD_ZERO (&watchset);
  FD_SET (event->sockfd, &watchset);
  select (event->sockfd + 1, &watchset, NULL, NULL, NULL);
  if (event->rbp == 0)
    {
      if ((bc = recv (event->sockfd, event->rbuf, 1, 0)) == -1)
	{
	  if (errno == EWOULDBLOCK)
	    {
	      return 0;
	    }
	  else
	    {
	      return -1;
	    }
	}
      event->rbp += bc;
    }
  if (bc == 0)
    return -1;
  if (event->rbp != 0)
    {
      if ((event->rbuf[0] & 0x10) != 0)
	{
	  event->clock = 0;
	  if (event->rbuf[0] == 0x10)
	    {
	      event->rbp = 0;
	      return 1;
	    }
	}
      if ((event->rbuf[0] & 0x08) != 0)
	rbc += 10;
      if ((event->rbuf[0] & 0x04) != 0)
	rbc += 9;
      if ((event->rbuf[0] & 0x02) != 0)
	rbc += 130;
      if ((event->rbuf[0] & 0x01) != 0)
	rbc += 15;
    }
  if ((bc =
       recv (event->sockfd, event->rbuf + event->rbp, rbc - event->rbp,
	     0)) == -1)
    {
      if (errno == EWOULDBLOCK)
	{
	  return 0;
	}
      else
	{
	  return -1;
	}
    }
  if (bc == 0)
    return -1;
  event->rbp += bc;
  if (event->rbp < rbc)
    return 0;

  rbc = 1;
  if ((event->rbuf[0] & 0x08) != 0)
    {
      event->aux2_change = 1;
      event->buffer_read_latency = (event->rbuf[rbc]) >> 4;
      event->job_running = ((event->rbuf[rbc]) >> 1) & 0x01;
      event->job_done = (event->rbuf[rbc++]) & 0x01;
      event->job_error = 0;
      for (bc = 0; bc < 8; bc++)
	{
	  event->job_error = ((event->job_error) << 8) | event->rbuf[rbc++];
	}
      event->job_cack_llcmd = ((event->rbuf[rbc]) >> 3) & 0x01;
      event->job_yield = ((event->rbuf[rbc]) >> 2) & 0x01;
      event->timebase_request = ((event->rbuf[rbc]) >> 1) & 0x01;
      event->parity_enable = (event->rbuf[rbc++]) & 0x01;
    }
  else
    {
      event->aux2_change = 0;
    }
  if ((event->rbuf[0] & 0x04) != 0)
    {
      event->mmio_ack = 1;
      event->mmio_rdata = 0;
      for (bc = 0; bc < 8; bc++)
	{
	  event->mmio_rdata = ((event->mmio_rdata) << 8) | event->rbuf[rbc++];
	}
      event->mmio_rdata_parity = event->rbuf[rbc++];
    }
  else
    {
      event->mmio_ack = 0;
    }
  if ((event->rbuf[0] & 0x02) != 0)
    {
      event->buffer_rdata_valid = 1;
      for (bc = 0; bc < 128; bc++)
	{
	  event->buffer_rdata[bc] = event->rbuf[rbc++];
	}
      for (bc = 0; bc < 2; bc++)
	{
	  event->buffer_rparity[bc] = event->rbuf[rbc++];
	}
    }
  else
    {
      event->buffer_rdata_valid = 0;
    }
  if ((event->rbuf[0] & 0x01) != 0)
    {
      event->command_valid = 1;
      event->command_tag = event->rbuf[rbc++];
      event->command_abort = (event->rbuf[rbc] >> 4) & 0x7;
      event->command_code = (event->rbuf[rbc++] & 0x0F) << 8;
      event->command_code = event->command_code | event->rbuf[rbc++];
      event->command_tag_parity = (event->rbuf[rbc] >> 6) & 0x01;
      event->command_code_parity = (event->rbuf[rbc] >> 5) & 0x01;
      event->command_address_parity = (event->rbuf[rbc] >> 4) & 0x01;
      event->command_size = (event->rbuf[rbc++] & 0x0F) << 8;
      event->command_size = event->command_size | event->rbuf[rbc++];
      event->command_address = 0;
      for (bc = 0; bc < 8; bc++)
	{
	  event->command_address =
	    ((event->command_address) << 8) | event->rbuf[rbc++];
	}
      event->command_handle = 0;
      for (bc = 0; bc < 2; bc++)
	{
	  event->command_handle =
	    ((event->command_handle) << 8) | event->rbuf[rbc++];
	}
    }
  else
    {
      event->command_valid = 0;
    }
  event->rbp = 0;
  return 1;
}

/* This function checks the socket connection for data from the external PSL
 * simulator. It needs to be called periodically to poll the socket connection.
 * (every clock cycle)  It will update the AFU_EVENT structure and returns a 1
 * if there are new events to process. */

int
psl_get_psl_events (struct AFU_EVENT *event)
{
  int bc;
  uint32_t rbc = 1;
  if (event->rbp == 0)
    {
      if ((bc = recv (event->sockfd, event->rbuf, 1, 0)) == -1)
	{
	  if (errno == EWOULDBLOCK)
	    {
	      return 0;
	    }
	  else
	    {
	      return -1;
	    }
	}
      if (bc == 0)
	return -1;
      event->rbp += bc;
    }
  if (event->rbp != 0)
    {
      if ((event->rbuf[0] & 0x40) != 0)
	{
	  event->clock = 1;
	  psl_signal_psl_model (event);
	  if (event->rbuf[0] == 0x40)
	    {
	      event->rbp = 0;
	      return 1;
	    }
	}
      if ((event->rbuf[0] & 0x20) != 0)
	rbc += 1;
      if ((event->rbuf[0] & 0x10) != 0)
	rbc += 10;
      if ((event->rbuf[0] & 0x08) != 0)
	rbc += 12;
      if ((event->rbuf[0] & 0x04) != 0)
	rbc += 6;
      if ((event->rbuf[0] & 0x02) != 0)
	rbc += 3;
      if ((event->rbuf[0] & 0x01) != 0)
	rbc += 133;
      if ((bc =
	   recv (event->sockfd, event->rbuf + event->rbp, rbc - event->rbp,
		 0)) == -1)
	{
	  if (errno == EWOULDBLOCK)
	    {
	      return 0;
	    }
	  else
	    {
	      return -1;
	    }
	}
      if (bc == 0)
	return -1;
      event->rbp += bc;
    }
  if (event->rbp < rbc)
    return 0;
  rbc = 1;
  if (event->rbuf[0] & 0x20)
    {
      event->aux1_change = 1;
      event->room = event->rbuf[rbc++];
    }
  else
    {
      event->aux1_change = 0;
    }
  if (event->rbuf[0] & 0x10)
    {
      event->job_valid = 1;
      event->job_code = event->rbuf[rbc++];
      event->job_address = 0;
      for (bc = 0; bc < 8; bc++)
	{
	  event->job_address =
	    ((event->job_address) << 8) | event->rbuf[rbc++];
	}
      event->job_address_parity = (event->rbuf[rbc] >> 1) & 0x01;
      event->job_code_parity = event->rbuf[rbc++] & 0x01;
    }
  else
    {
      event->job_valid = 0;
    }
  if (event->rbuf[0] & 0x08)
    {
      event->mmio_valid = 1;
      event->mmio_wdata_parity = ((event->rbuf[rbc]) >> 4) & 1;
      event->mmio_address_parity = ((event->rbuf[rbc]) >> 3) & 1;
      event->mmio_afudescaccess = ((event->rbuf[rbc]) >> 2) & 1;
      event->mmio_double = ((event->rbuf[rbc]) >> 1) & 1;
      event->mmio_read = (event->rbuf[rbc++]) & 1;
      event->mmio_address = 0;
      for (bc = 0; bc < 3; bc++)
	{
	  event->mmio_address =
	    ((event->mmio_address) << 8) | event->rbuf[rbc++];
	}
      event->mmio_wdata = 0;
      for (bc = 0; bc < 8; bc++)
	{
	  event->mmio_wdata = ((event->mmio_wdata) << 8) | event->rbuf[rbc++];
	}
    }
  else
    {
      event->mmio_valid = 0;
    }
  if (event->rbuf[0] & 0x04)
    {
      event->response_valid = 1;
      event->response_tag = event->rbuf[rbc++];
      event->response_tag_parity = event->rbuf[rbc++];
      event->response_code = event->rbuf[rbc++];
      event->cache_position = event->rbuf[rbc++] << 5;
      event->cache_position =
	event->cache_position | (((event->rbuf[rbc]) >> 3) & 0x1F);
      event->cache_state = ((event->rbuf[rbc]) >> 2) & 0x3;
      event->credits = (event->rbuf[rbc++] << 8) & 0x100;
      event->credits = event->credits | event->rbuf[rbc++];
    }
  else
    {
      event->response_valid = 0;
    }
  if (event->rbuf[0] & 0x02)
    {
      event->buffer_read = 1;
      event->buffer_read_tag = event->rbuf[rbc++];
      event->buffer_read_tag_parity = event->rbuf[rbc++];
      if ((event->rbuf[rbc]) >> 7)
	{
	  event->buffer_read_length = 128;
	}
      else
	{
	  event->buffer_read_length = 64;
	}
      event->buffer_read_address = (event->rbuf[rbc++]) & 0x3F;
    }
  else
    {
      event->buffer_read = 0;
    }
  if (event->rbuf[0] & 0x01)
    {
      event->buffer_write = 1;
      event->buffer_write_tag = event->rbuf[rbc++];
      event->buffer_write_tag_parity = event->rbuf[rbc++];
      if ((event->rbuf[rbc]) >> 7)
	{
	  event->buffer_write_length = 128;
	}
      else
	{
	  event->buffer_write_length = 64;
	}
      event->buffer_write_address = (event->rbuf[rbc++]) & 0x3F;
      for (bc = 0; bc < 128; bc++)
	{
	  event->buffer_wdata[bc] = event->rbuf[rbc++];
	}
      for (bc = 0; bc < 2; bc++)
	{
	  event->buffer_wparity[bc] = event->rbuf[rbc++];
	}
    }
  else
    {
      event->buffer_write = 0;
    }
  event->rbp = 0;
  return 1;
}

/* Call this on the AFU side to build a command to send to PSL */

int
psl_afu_command (struct AFU_EVENT *event,
		 uint32_t tag,
		 uint32_t tag_parity,
		 uint32_t code,
		 uint32_t code_parity,
		 uint64_t address,
		 uint64_t address_parity,
		 uint32_t size,
                 uint32_t abort,
                 uint32_t handle)
{
  if (event->command_valid)
    {
      return PSL_DOUBLE_COMMAND;
    }
  else
    {
      event->command_valid = 1;
      event->command_tag = tag;
      event->command_tag_parity = tag_parity;
      event->command_code = code;
      event->command_code_parity = code_parity;
      event->command_address = address;
      event->command_address_parity = address_parity;
      event->command_size = size;
      event->command_abort = abort;
      event->command_handle = handle;
      return PSL_SUCCESS;
    }
}

/* Call this on the AFU side to build an MMIO acknowledge. Read data is used
 * only for MMIO reads, ignored otherwise */

int
psl_afu_mmio_ack (struct AFU_EVENT *event,
		  uint64_t read_data,
		  uint32_t read_data_parity)
{
  if (event->mmio_ack)
    {
      return PSL_DOUBLE_COMMAND;
    }
  else
    {
      event->mmio_ack = 1;
      event->mmio_rdata = read_data;
      event->mmio_rdata_parity = read_data_parity;
      return PSL_SUCCESS;
    }
}

/* Call this on the AFU side to build buffer read data. Length should be
 * 64 or 128 */

int
psl_afu_read_buffer_data (struct AFU_EVENT *event,
			  uint32_t length,
			  uint8_t * read_data, uint8_t * read_parity)
{
  if (event->buffer_rdata_valid)
    {
      return PSL_DOUBLE_COMMAND;
    }
  else
    {
      event->buffer_rdata_valid = 1;
      memcpy (event->buffer_rdata, read_data, length);
      event->buffer_read_length = length;
      memcpy (event->buffer_rparity, read_parity, length / 64);
      return PSL_SUCCESS;
    }
}


/* Call this on the AFU side to change the auxilliary signals
 * (running, done, job error, buffer read latency) */

int
psl_afu_aux2_change (struct AFU_EVENT *event,
		     uint32_t running,
		     uint32_t done,
		     uint32_t cack_llcmd,
		     uint64_t job_error,
		     uint32_t yield,
		     uint32_t tb_request,
		     uint32_t par_enable,
		     uint32_t read_latency)
{
  if (event->aux2_change)
    {
      return PSL_DOUBLE_COMMAND;
    }
  else
    {
      event->aux2_change = 1;
      event->job_running = running;
      event->job_done = done;
      event->job_cack_llcmd = cack_llcmd;
      event->job_error = job_error;
      event->job_yield = yield;
      event->timebase_request = tb_request;
      event->parity_enable = par_enable;
      event->buffer_read_latency = read_latency;
      return PSL_SUCCESS;
    }
}
