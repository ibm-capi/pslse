#include <endian.h>
#include <inttypes.h>
#include <malloc.h>
#include <stdio.h>

#include "../common/debug.h"
#include "../common/psl_interface_t.h"
#include "../common/utils.h"

#define MAX_LINE_CHARS	1024

int parity, running, latency;

static char *_afu_name(uint8_t id)
{
	char *name;
	uint8_t major, minor;

	major = id >> 4;
	minor = id & 0xf;
	name = (char*) malloc(7);
	sprintf(name, "afu%d.%d", major, minor);
	return name;
}

static int _report_version(FILE *fp)
{
	uint8_t major;
	uint8_t minor;

	if (debug_get_8(fp, &major)<1)
		return -1;
	if (debug_get_8(fp, &minor)<1)
		return -1;

	printf("PSLSE_VERSION=%d.%03d\n", major, minor);

	return 0;
}

static int _parse_parm(FILE *fp)
{
	uint32_t parm;
	uint32_t value;

	if (debug_get_32(fp, &parm)<1)
		return -1;
	if (debug_get_32(fp, &value)<1)
		return -1;

	switch (parm) {
	case DBG_PARM_SEED:
		printf("PARM:SEED=%d\n", value);
		break;
	case DBG_PARM_TIMEOUT:
		printf("PARM:TIMEOUT=%d\n", value);
		break;
	case DBG_PARM_RESP_PERCENT:
		printf("PARM:REPSONSE_PERCENT=%d\n", value);
		break;
	case DBG_PARM_PAGED_PERCENT:
		printf("PARM:PAGED_PERCENT=%d\n", value);
		break;
	case DBG_PARM_REORDER_PERCENT:
		printf("PARM:REORDER_PERCENT=%d\n", value);
		break;
	case DBG_PARM_BUFFER_PERCENT:
		printf("PARM:BUFFER_PERCENT=%d\n", value);
		break;
	default:
		return -1;
	}

	return 0;
}

static int _parse_afu(FILE *fp, DBG_HEADER header)
{
	uint8_t id;
	char *name;

	if (debug_get_8(fp, &id)<1)
		return -1;
	name = _afu_name(id);

	switch(header) {
	case DBG_HEADER_AFU_CONNECT:
		printf("%s:Connect\n", name);
		break;
	case DBG_HEADER_AFU_DROP:
		printf("%s:Disconnect\n", name);
		break;
	default:
		free(name);
		return -1;
	}
	free(name);
	return 0;
}

static int _parse_context(FILE *fp, DBG_HEADER header)
{
	uint16_t context;
	uint8_t id;
	char *name;

	if (debug_get_8(fp, &id)<1)
		return -1;
	if (debug_get_16(fp, &context)<1)
		return -1;
	name = _afu_name(id);

	switch(header) {
	case DBG_HEADER_CONTEXT_ADD:
		printf("%s:CLIENT: Added context %d\n", name, context);
		break;
	case DBG_HEADER_CONTEXT_REMOVE:
		printf("%s:CLIENT: Removed context %d\n", name, context);
		break;
	default:
		free(name);
		return -1;
	}
	free(name);
	return 0;
}

static int _parse_job(FILE *fp, DBG_HEADER header)
{
	uint32_t code;
	uint8_t id;
	char *name;

	if (debug_get_8(fp, &id)<1)
		return -1;
	if (debug_get_32(fp, &code)<1)
		return -1;
	name = _afu_name(id);

	printf("%s:JOB: ", name);
	switch (header) {
	case DBG_HEADER_JOB_ADD:
		printf("Added ");
		break;
	case DBG_HEADER_JOB_SEND:
		printf("Sent ");
		break;
	default:
		free(name);
		return -1;
	}
	switch (code) {
	case PSL_JOB_START:
		printf("START");
		break;
	case PSL_JOB_RESET:
		printf("RESET");
		break;
	default:
		printf("Unknown:0x%08x", code);
	}
	printf("\n");
	free(name);
	return 0;
}

static int _parse_map(FILE *fp, DBG_HEADER header)
{
	uint16_t context;
	uint8_t id;
	char *name;

	if (debug_get_8(fp, &id)<1)
		return -1;
	if (debug_get_16(fp, &context)<1)
		return -1;
	name = _afu_name(id);

	printf("%s:MMIO: Mapped context %d\n", name, context);
	free(name);
	return 0;
}

static int _parse_mmio(FILE *fp, DBG_HEADER header)
{
	uint32_t addr;
	uint16_t context;
	uint8_t id, rnw, dw;
	char *name;

	if (debug_get_8(fp, &id)<1)
		return -1;
	if (debug_get_8(fp, &rnw)<1)
		return -1;
	if (debug_get_8(fp, &dw)<1)
		return -1;
	if (debug_get_16(fp, &context)<1)
		return -1;
	if (debug_get_32(fp, &addr)<1)
		return -1;
	name = _afu_name(id);

	printf("%s", name);
	if (header==DBG_HEADER_MMIO_ADD) {
		if (((int16_t) context)!=-1)
			printf(",%d", context);
		printf(":MMIO: Added ");
		if (((int16_t) context)==-1)
			printf("Descriptor ");
	}
	else {
		printf(":MMIO: Sent ");
		if (((int16_t) context)==1)
			printf("Descriptor ");
	}
	if (rnw)
		printf("Read");
	else
		printf("Write");
	if (dw)
		printf("64 ");
	else
		printf("32 ");
	printf("Address=0x%06x\n", addr);
	free(name);

	return 0;
}

static int _parse_mmio_ack(FILE *fp, DBG_HEADER header)
{
	uint8_t id;
	char *name;

	if (debug_get_8(fp, &id)<1)
		return -1;
	name = _afu_name(id);

	printf("%s:MMIO: Ack\n", name);
	free(name);
	return 0;
}

static int _parse_mmio_return(FILE *fp, DBG_HEADER header)
{
	uint16_t context;
	uint8_t id;
	char *name;

	if (debug_get_8(fp, &id)<1)
		return -1;
	if (debug_get_16(fp, &context)<1)
		return -1;
	name = _afu_name(id);

	printf("%s,%d:MMIO: Return\n", name, context);
	free(name);
	return 0;
}

static int _parse_cmd_add(FILE *fp, DBG_HEADER header)
{
	uint16_t context, command;
	uint8_t id, tag;
	char *name;

	if (debug_get_8(fp, &id)<1)
		return -1;
	if (debug_get_8(fp, &tag)<1)
		return -1;
	if (debug_get_16(fp, &context)<1)
		return -1;
	if (debug_get_16(fp, &command)<1)
		return -1;
	name = _afu_name(id);

	printf("%s,%d:CMD: New tag=0x%02x code=0x%04x\n", name, context,
	       tag, command);
	free(name);

	return 0;
}

static int _parse_cmd_update(FILE *fp, DBG_HEADER header)
{
	uint16_t context, resp;
	uint8_t id, tag;
	char *name;

	if (debug_get_8(fp, &id)<1)
		return -1;
	if (debug_get_8(fp, &tag)<1)
		return -1;
	if (debug_get_16(fp, &context)<1)
		return -1;
	if (debug_get_16(fp, &resp)<1)
		return -1;
	name = _afu_name(id);

	printf("%s,%d:CMD: Update tag=0x%02x resp=0x%02x\n", name, context,
	       tag, resp);
	free(name);

	return 0;
}

static int _parse_cmd_client(FILE *fp, DBG_HEADER header)
{
	uint16_t context;
	uint8_t id, tag;
	char *name;

	if (debug_get_8(fp, &id)<1)
		return -1;
	if (debug_get_8(fp, &tag)<1)
		return -1;
	if (debug_get_16(fp, &context)<1)
		return -1;
	name = _afu_name(id);

	printf("%s,%d:CMD: Client ", name, context);
	if (header==DBG_HEADER_CMD_CLIENT_REQ)
		printf("Request");
	else
		printf("Return");
	printf(" tag=0x%02x\n", tag);
	free(name);

	return 0;
}

static int _parse_cmd_buffer(FILE *fp, DBG_HEADER header)
{
	uint8_t id, tag;
	char *name;

	if (debug_get_8(fp, &id)<1)
		return -1;
	if (debug_get_8(fp, &tag)<1)
		return -1;
	name = _afu_name(id);

	printf("%s:CMD: Buffer ", name);
	if (header==DBG_HEADER_CMD_BUFFER_WRITE)
		printf("Write");
	else
		printf("Read");
        printf(" request tag=0x%02x\n", tag);
	free(name);

	return 0;
}

static int _parse_cmd_response(FILE *fp, DBG_HEADER header)
{
	uint8_t id, tag;
	char *name;

	if (debug_get_8(fp, &id)<1)
		return -1;
	if (debug_get_8(fp, &tag)<1)
		return -1;
	name = _afu_name(id);

	printf("%s:CMD: Response tag=0x%02x\n", name, tag);
	free(name);

	return 0;
}

static void _aux2_banner(int *printed, char *name)
{
	if (!(*printed))
		printf("%s:AUX2:", name);
	*printed = 1;
}

static int _parse_aux(FILE *fp, DBG_HEADER header)
{
	uint64_t error = 0;
	uint8_t aux2;
	uint8_t id;
	char *name;
	int banner = 0;

	if (debug_get_8(fp, &id)<1)
		return -1;
	if (debug_get_8(fp, &aux2)<1)
		return -1;
	name = _afu_name(id);
	if ((aux2 && DBG_AUX2_DONE)==DBG_AUX2_DONE) {
		if (debug_get_64(fp, &error)<1)
			return -1;
	}

	if (latency != (aux2 & DBG_AUX2_LAT_MASK)) {
		latency = aux2 & DBG_AUX2_LAT_MASK;
		_aux2_banner(&banner, name);
		printf(" brlat=%d", latency);
	}
	if ((aux2 & DBG_AUX2_PAREN)==DBG_AUX2_PAREN) {
		if (!parity) {
			_aux2_banner(&banner, name);
			printf(" parity=1");
		}
		parity = 1;
	}
	else {
		if (parity) {
			_aux2_banner(&banner, name);
			printf(" parity=0");
		}
		parity = 0;
	}
	if ((aux2 & DBG_AUX2_TBREQ)==DBG_AUX2_TBREQ) {
		_aux2_banner(&banner, name);
		printf(" tbreq");
	}
	if ((aux2 & DBG_AUX2_LLCACK)==DBG_AUX2_LLCACK) {
		_aux2_banner(&banner, name);
		printf(" lcack");
	}
	if ((aux2 & DBG_AUX2_RUNNING)==DBG_AUX2_RUNNING) {
		if (!running) {
			_aux2_banner(&banner, name);
			printf(" jrunning=1");
		}
		running = 1;
	}
	else {
		if (running) {
			_aux2_banner(&banner, name);
			printf(" jrunning=0");
		}
		running = 0;
	}
	if ((aux2 & DBG_AUX2_DONE)==DBG_AUX2_DONE) {
		_aux2_banner(&banner, name);
		printf(" jdone");
	}
	if (error) {
		_aux2_banner(&banner, name);
		printf(" jerror=%016"PRIx64, error);
	}
	if (banner)
		printf("\n");
	free(name);
	
	return 0;
}

static int _parse_socket(FILE *fp, DBG_HEADER header, int silent)
{
	uint8_t id, type;
	uint16_t context;
	char *name;

	if (debug_get_8(fp, &id)<1)
		return -1;
	if (debug_get_8(fp, &type)<1)
		return -1;
	if (debug_get_16(fp, &context)<1)
		return -1;

	if (silent)
		return 0;

	if (id != (uint8_t)-1) {
		name = _afu_name(id);
		printf("%s", name);
		if (context != (uint16_t)-1)
			printf(",%d", context);
		printf(":");
		free(name);
	}
	printf("SOCKET ");
	switch (header) {
	case DBG_HEADER_SOCKET_PUT:
		printf("OUT: ");
		break;
	default:
		printf("IN: ");
		break;
	}
	switch (type) {
	case 'P':
		printf("PSLSE");
		break;
	case PSLSE_CONNECT:
		printf("CONNECT");
		break;
	case PSLSE_QUERY:
		printf("QUERY");
		break;
	case PSLSE_OPEN:
		printf("OPEN");
		break;
	case PSLSE_ATTACH:
		printf("ATTACH");
		break;
	case PSLSE_DETACH:
		printf("DETACH");
		break;
	case PSLSE_MEMORY_READ:
		printf("READ");
		break;
	case PSLSE_MEMORY_WRITE:
		printf("WRITE");
		break;
	case PSLSE_MEMORY_TOUCH:
		printf("TOUCH");
		break;
	case PSLSE_MEM_SUCCESS:
		printf("MEM ACK");
		break;
	case PSLSE_MEM_FAILURE:
		printf("MEM FAIL");
		break;
	case PSLSE_MMIO_MAP:
		printf("MAP");
		break;
	case PSLSE_MMIO_READ64:
		printf("READ64");
		break;
	case PSLSE_MMIO_WRITE64:
		printf("WRITE64");
		break;
	case PSLSE_MMIO_READ32:
		printf("READ32");
		break;
	case PSLSE_MMIO_WRITE32:
		printf("WRITE32");
		break;
	case PSLSE_MMIO_ACK:
		printf("MMIO ACK");
		break;
	case PSLSE_MMIO_FAIL:
		printf("MMIO FAIL");
		break;
	case PSLSE_INTERRUPT:
		printf("INTERRRUPT");
		break;
	default :
		printf("Unknown:0x%02x", type);
	}
	printf("\n");
	return 0;
}

int main(int argc, char **argv)
{
	FILE *fp;
	DBG_HEADER header;
	int silent;

	if((fp = fopen("debug.log", "r"))==NULL) {
		perror("fopen:debug.log");
		return -1;
	}

	while ((header = debug_get_header(fp))!=(DBG_HEADER)-1)
	{
		silent = 0;
		switch (header) {
		case DBG_HEADER_VERSION:
			_report_version(fp);
			break;
		case DBG_HEADER_PARM:
			if (_parse_parm(fp) < 0)
				return -1;
			break;
		case DBG_HEADER_AFU_CONNECT:
		case DBG_HEADER_AFU_DROP:
			if (_parse_afu(fp, header) < 0)
				return -1;
			break;
		case DBG_HEADER_CONTEXT_ADD:
		case DBG_HEADER_CONTEXT_REMOVE:
			if (_parse_context(fp, header) < 0)
				return -1;
			break;
		case DBG_HEADER_JOB_ADD:
		case DBG_HEADER_JOB_SEND:
			if (_parse_job(fp, header) < 0)
				return -1;
			break;
		case DBG_HEADER_JOB_AUX2:
			if (_parse_aux(fp, header) < 0)
				return -1;
			break;
		case DBG_HEADER_MMIO_MAP:
			if (_parse_map(fp, header) < 0)
				return -1;
			break;
		case DBG_HEADER_MMIO_ADD:
		case DBG_HEADER_MMIO_SEND:
			if (_parse_mmio(fp, header) < 0)
				return -1;
			break;
		case DBG_HEADER_MMIO_ACK:
			if (_parse_mmio_ack(fp, header) < 0)
				return -1;
			break;
		case DBG_HEADER_MMIO_RETURN:
			if (_parse_mmio_return(fp, header) < 0)
				return -1;
			break;
		case DBG_HEADER_CMD_ADD:
			if (_parse_cmd_add(fp, header) < 0)
				return -1;
			break;
		case DBG_HEADER_CMD_UPDATE:
			if (_parse_cmd_update(fp, header) < 0)
				return -1;
			break;
		case DBG_HEADER_CMD_CLIENT_ACK:
		case DBG_HEADER_CMD_CLIENT_REQ:
			if (_parse_cmd_client(fp, header) < 0)
				return -1;
			break;
		case DBG_HEADER_CMD_BUFFER_WRITE:
		case DBG_HEADER_CMD_BUFFER_READ:
			if (_parse_cmd_buffer(fp, header) < 0)
				return -1;
			break;
		case DBG_HEADER_CMD_RESPONSE:
			if (_parse_cmd_response(fp, header) < 0)
				return -1;
			break;
		case DBG_HEADER_SOCKET_GET:
		case DBG_HEADER_SOCKET_PUT:
			if (_parse_socket(fp, header, silent) < 0)
				return -1;
			break;
		default:
			printf("Bad header: %d\n", header);
			return -1;
		}
		header = 0;
	}

	fclose(fp);
	return 0;
}
