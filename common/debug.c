#include <endian.h>
#include <inttypes.h>
#include <malloc.h>
#include <stdio.h>

#include "debug.h"
#include "psl_interface_t.h"

static DBG_HEADER adjust_header(DBG_HEADER header)
{
	switch (sizeof(header)) {
	case sizeof(uint64_t):	/*constant condition */
		header = htole64(header);
		break;
	case sizeof(uint32_t):	/*constant condition */
		header = htole32(header);
		break;
	case sizeof(uint16_t):	/*constant condition */
		header = htole16(header);
		break;
	default:
		break;
	}
	return header;
}

static void _debug_send_id(FILE * fp, DBG_HEADER header, uint8_t id)
{
	char *buffer;
	size_t size;
	int offset;

	offset = 0;
	header = adjust_header(header);
	size = sizeof(DBG_HEADER) + sizeof(id);
	if ((buffer = (char *)malloc(size)) != NULL) {
		memcpy(buffer, (char *)&header, sizeof(DBG_HEADER));
		offset += sizeof(DBG_HEADER);
		buffer[offset] = id;
		fwrite(buffer, size, 1, fp);
		free(buffer);
	}
}

static void _debug_send_id_8(FILE * fp, DBG_HEADER header, uint8_t id,
			     uint8_t value)
{
	char *buffer;
	size_t size;
	int offset;

	offset = 0;
	header = adjust_header(header);
	size = sizeof(DBG_HEADER) + sizeof(id) + sizeof(value);
	if ((buffer = (char *)malloc(size)) != NULL) {
		memcpy(buffer, (char *)&header, sizeof(DBG_HEADER));
		offset += sizeof(header);
		buffer[offset] = id;
		offset += sizeof(id);
		buffer[offset] = value;
		fwrite(buffer, size, 1, fp);
		free(buffer);
	}
}

static void _debug_send_id_16(FILE * fp, DBG_HEADER header, uint8_t id,
			      uint16_t value)
{
	char *buffer;
	size_t size;
	int offset;

	offset = 0;
	header = adjust_header(header);
	size = sizeof(DBG_HEADER) + sizeof(id) + sizeof(value);
	if ((buffer = (char *)malloc(size)) != NULL) {
		memcpy(buffer, (char *)&header, sizeof(DBG_HEADER));
		offset += sizeof(header);
		buffer[offset] = id;
		offset += sizeof(id);
		value = htole16(value);
		memcpy(buffer + offset, (char *)&value, sizeof(value));
		fwrite(buffer, size, 1, fp);
		free(buffer);
	}
}

static void _debug_send_id_32(FILE * fp, DBG_HEADER header, uint8_t id,
			      uint32_t value)
{
	char *buffer;
	size_t size;
	int offset;

	offset = 0;
	header = adjust_header(header);
	size = sizeof(DBG_HEADER) + sizeof(id) + sizeof(value);
	if ((buffer = (char *)malloc(size)) != NULL) {
		memcpy(buffer, (char *)&header, sizeof(DBG_HEADER));
		offset += sizeof(header);
		buffer[offset] = id;
		offset += sizeof(id);
		value = htole32(value);
		memcpy(buffer + offset, (char *)&value, sizeof(value));
		fwrite(buffer, size, 1, fp);
		free(buffer);
	}
}

static void _debug_send_32_32(FILE * fp, DBG_HEADER header, uint32_t value0,
			      uint32_t value1)
{
	char *buffer;
	size_t size;
	int offset;

	offset = 0;
	header = adjust_header(header);
	size = sizeof(DBG_HEADER) + sizeof(value0) + sizeof(value1);
	if ((buffer = (char *)malloc(size)) != NULL) {
		memcpy(buffer, (char *)&header, sizeof(DBG_HEADER));
		offset += sizeof(header);
		value0 = htole32(value0);
		memcpy(buffer + offset, (char *)&value0, sizeof(value0));
		offset += sizeof(value0);
		value0 = htole32(value1);
		memcpy(buffer + offset, (char *)&value1, sizeof(value1));
		fwrite(buffer, size, 1, fp);
		free(buffer);
	}
}

static void _debug_send_id_8_16(FILE * fp, DBG_HEADER header, uint8_t id,
				uint8_t value0, uint16_t value1)
{
	char *buffer;
	size_t size;
	int offset;

	offset = 0;
	header = adjust_header(header);
	size =
	    sizeof(DBG_HEADER) + sizeof(id) + sizeof(value0) + sizeof(value1);
	if ((buffer = (char *)malloc(size)) != NULL) {
		memcpy(buffer, (char *)&header, sizeof(DBG_HEADER));
		offset += sizeof(header);
		buffer[offset] = id;
		offset += sizeof(id);
		buffer[offset] = value0;
		offset += sizeof(value0);
		value1 = htole16(value1);
		memcpy(buffer + offset, (char *)&value1, sizeof(value1));
		fwrite(buffer, size, 1, fp);
		free(buffer);
	}
}

static void _debug_send_id_8_16_16(FILE * fp, DBG_HEADER header, uint8_t id,
				   uint8_t value0, uint16_t value1,
				   uint16_t value2)
{
	char *buffer;
	size_t size;
	int offset;

	offset = 0;
	header = adjust_header(header);
	size =
	    sizeof(DBG_HEADER) + sizeof(id) + sizeof(value0) + sizeof(value1) +
	    sizeof(value2);
	if ((buffer = (char *)malloc(size)) != NULL) {
		memcpy(buffer, (char *)&header, sizeof(DBG_HEADER));
		offset += sizeof(header);
		buffer[offset] = id;
		offset += sizeof(id);
		buffer[offset] = value0;
		offset += sizeof(value0);
		value1 = htole16(value1);
		memcpy(buffer + offset, (char *)&value1, sizeof(value1));
		offset += sizeof(value1);
		value2 = htole16(value2);
		memcpy(buffer + offset, (char *)&value2, sizeof(value2));
		fwrite(buffer, size, 1, fp);
		free(buffer);
	}
}

static void _debug_send_id_8_8_16_32(FILE * fp, DBG_HEADER header, uint8_t id,
				     uint8_t value0, uint8_t value1,
				     uint16_t value2, uint32_t value3)
{
	char *buffer;
	size_t size;
	int offset;

	offset = 0;
	header = adjust_header(header);
	size =
	    sizeof(DBG_HEADER) + sizeof(id) + sizeof(value0) + sizeof(value1) +
	    sizeof(value2) + sizeof(value3);
	if ((buffer = (char *)malloc(size)) != NULL) {
		memcpy(buffer, (char *)&header, sizeof(DBG_HEADER));
		offset += sizeof(header);
		buffer[offset] = id;
		offset += sizeof(id);
		buffer[offset] = value0;
		offset += sizeof(value0);
		buffer[offset] = value1;
		offset += sizeof(value1);
		value2 = htole16(value2);
		memcpy(buffer + offset, (char *)&value2, sizeof(value2));
		offset += sizeof(value2);
		value3 = htole32(value3);
		memcpy(buffer + offset, (char *)&value3, sizeof(value3));
		fwrite(buffer, size, 1, fp);
		free(buffer);
	}
}

size_t debug_get_64(FILE * fp, uint64_t * value)
{
	size_t rc;
	rc = fread((char *)value, sizeof(uint64_t), 1, fp);
	*value = le64toh(*value);
	return rc;
}

size_t debug_get_32(FILE * fp, uint32_t * value)
{
	size_t rc;
	rc = fread((char *)value, sizeof(uint32_t), 1, fp);
	*value = le32toh(*value);
	return rc;
}

size_t debug_get_16(FILE * fp, uint16_t * value)
{
	size_t rc;
	rc = fread((char *)value, sizeof(uint16_t), 1, fp);
	*value = le16toh(*value);
	return rc;
}

size_t debug_get_8(FILE * fp, uint8_t * value)
{
	return fread((char *)value, sizeof(uint8_t), 1, fp);
}

DBG_HEADER debug_get_header(FILE * fp)
{
	DBG_HEADER header;

	switch (sizeof(DBG_HEADER)) {
	case sizeof(uint64_t):	/*constant condition */
		if (debug_get_64(fp, (uint64_t *) & header) != 1)
			return -1;
		break;
	case sizeof(uint32_t):	/*constant condition */
		if (debug_get_32(fp, (uint32_t *) & header) != 1)
			return -1;
		break;
	case sizeof(uint16_t):	/*constant condition */
		if (debug_get_16(fp, (uint16_t *) & header) != 1)
			return -1;
		break;
	default:
		if (debug_get_8(fp, (uint8_t *) & header) != 1)
			return -1;
		break;
	}
	return header;
}

void debug_send_version(FILE * fp, uint8_t major, uint8_t minor)
{
	char *buffer;
	size_t size;
	int offset;
	DBG_HEADER header;

	offset = 0;
	header = adjust_header(DBG_HEADER_VERSION);
	size = sizeof(DBG_HEADER) + sizeof(major) + sizeof(minor);
	if ((buffer = (char *)malloc(size)) != NULL) {
		memcpy(buffer, (char *)&header, sizeof(DBG_HEADER));
		offset += sizeof(header);
		buffer[offset] = major;
		offset += sizeof(major);
		buffer[offset] = minor;
		fwrite(buffer, size, 1, fp);
		free(buffer);
	}
}

void debug_afu_connect(FILE * fp, uint8_t id)
{
	_debug_send_id(fp, DBG_HEADER_AFU_CONNECT, id);
}

void debug_afu_drop(FILE * fp, uint8_t id)
{
	_debug_send_id(fp, DBG_HEADER_AFU_DROP, id);
}

void debug_job_add(FILE * fp, uint8_t id, uint32_t code)
{
	_debug_send_id_32(fp, DBG_HEADER_JOB_ADD, id, code);
}

void debug_job_send(FILE * fp, uint8_t id, uint32_t code)
{
	_debug_send_id_32(fp, DBG_HEADER_JOB_SEND, id, code);
}

void debug_job_aux2(FILE * fp, uint8_t id, uint8_t aux2)
{
	_debug_send_id_8(fp, DBG_HEADER_JOB_AUX2, id, aux2);
}

void debug_context_add(FILE * fp, uint8_t id, uint16_t context)
{
	_debug_send_id_16(fp, DBG_HEADER_CONTEXT_ADD, id, context);
}

void debug_context_remove(FILE * fp, uint8_t id, uint16_t context)
{
	_debug_send_id_16(fp, DBG_HEADER_CONTEXT_REMOVE, id, context);
}

void debug_mmio_map(FILE * fp, uint8_t id, uint16_t context)
{
	_debug_send_id_16(fp, DBG_HEADER_MMIO_MAP, id, context);
}

void debug_parm(FILE * fp, uint32_t parm, uint32_t value)
{
	_debug_send_32_32(fp, DBG_HEADER_PARM, parm, value);
}

void debug_mmio_add(FILE * fp, uint8_t id, uint16_t context, uint8_t rnw,
		    uint8_t dw, uint32_t addr)
{
	_debug_send_id_8_8_16_32(fp, DBG_HEADER_MMIO_ADD, id, rnw, dw, context,
				 addr);
}

void debug_mmio_send(FILE * fp, uint8_t id, uint16_t context, uint8_t rnw,
		     uint8_t dw, uint32_t addr)
{
	_debug_send_id_8_8_16_32(fp, DBG_HEADER_MMIO_SEND, id, rnw, dw, context,
				 addr);
}

void debug_mmio_ack(FILE * fp, uint8_t id)
{
	_debug_send_id(fp, DBG_HEADER_MMIO_ACK, id);
}

void debug_mmio_return(FILE * fp, uint8_t id, uint16_t context)
{
	_debug_send_id_16(fp, DBG_HEADER_MMIO_RETURN, id, context);
}

void debug_cmd_add(FILE * fp, uint8_t id, uint8_t tag, uint16_t context,
		   uint16_t command)
{
	_debug_send_id_8_16_16(fp, DBG_HEADER_CMD_ADD, id, tag, context,
			       command);
}

void debug_cmd_update(FILE * fp, uint8_t id, uint8_t tag, uint16_t context,
		      uint16_t resp)
{
	_debug_send_id_8_16_16(fp, DBG_HEADER_CMD_UPDATE, id, tag, context,
			       resp);
}

void debug_cmd_client(FILE * fp, uint8_t id, uint8_t tag, uint16_t context)
{
	_debug_send_id_8_16(fp, DBG_HEADER_CMD_CLIENT_REQ, id, tag, context);
}

void debug_cmd_return(FILE * fp, uint8_t id, uint8_t tag, uint16_t context)
{
	_debug_send_id_8_16(fp, DBG_HEADER_CMD_CLIENT_ACK, id, tag, context);
}

void debug_cmd_buffer_write(FILE * fp, uint8_t id, uint8_t tag)
{
	_debug_send_id_8(fp, DBG_HEADER_CMD_BUFFER_WRITE, id, tag);
}

void debug_cmd_buffer_read(FILE * fp, uint8_t id, uint8_t tag)
{
	_debug_send_id_8(fp, DBG_HEADER_CMD_BUFFER_READ, id, tag);
}

void debug_cmd_response(FILE * fp, uint8_t id, uint8_t tag)
{
	_debug_send_id_8(fp, DBG_HEADER_CMD_RESPONSE, id, tag);
}

void debug_socket_put(FILE * fp, uint8_t id, uint16_t context, uint8_t type)
{
	_debug_send_id_8_16(fp, DBG_HEADER_SOCKET_PUT, id, type, context);
}

void debug_socket_get(FILE * fp, uint8_t id, uint16_t context, uint8_t type)
{
	_debug_send_id_8_16(fp, DBG_HEADER_SOCKET_GET, id, type, context);
}
