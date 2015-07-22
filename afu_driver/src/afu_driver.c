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

#include <malloc.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "psl_interface.h"
#include "vpi_user.h"

#define CLOCK_EDGE_DELAY 2
#define CACHELINE_BYTES 128

struct resp_event {
	uint32_t tag;
	uint32_t tagpar;
	uint32_t code;
	int32_t credits;
	struct resp_event *__next;
};

// Global variables

static unsigned int bw_delay;
static struct AFU_EVENT event;
static struct resp_event *resp_list;
static vpiHandle pclock;
static vpiHandle jval, jcom, jcompar, jea, jeapar, jrunning, jdone, jcack,
    jerror, latency, jyield, timebase_req, parity_enabled;
static vpiHandle mmval, mmcfg, mmrnw, mmdw, mmad, mmadpar, mmwdata, mmwdatapar,
    mmack, mmrdata, mmrdatapar;
static vpiHandle croom, cvalid, ctag, ctagpar, ccom, ccompar, cabt, cea,
    ceapar, cch, csize;
static vpiHandle brval, brtag, brtagpar, brdata, brpar, brvalid_out, brtag_out,
    brlat;
static vpiHandle bwval, bwtag, bwtagpar, bwdata, bwpar;
static vpiHandle rval, rtag, rtagpar, resp, rcredits;
static int cl_jval, cl_mmio, cl_br, cl_bw, cl_rval;

// Function declaration

static void psl(void);

// VPI abstraction functions

static long long get_time()
{
	s_vpi_time time;
	time.type = vpiSimTime;
	vpi_get_time(NULL, &time);
	uint64_t long_time;
	long_time = time.high;
	long_time <<= 32;
	long_time += time.low;
	return (long long)long_time;
}

static void set_signal32(vpiHandle signal, uint32_t data)
{
	s_vpi_value value;
	value.format = vpiIntVal;
	value.value.integer = data;
	vpi_put_value(signal, &value, NULL, vpiNoDelay);
}

static void set_signal64(vpiHandle signal, uint64_t data)
{
	s_vpi_value value;
	value.format = vpiVectorVal;
	value.value.vector = (s_vpi_vecval *) calloc(2, sizeof(s_vpi_vecval));
	value.value.vector[1].aval = (int)(data >> 32);
	value.value.vector[1].bval = 0;
	value.value.vector[0].aval = (int)(data & 0xffffffff);
	value.value.vector[0].bval = 0;
	vpi_put_value(signal, &value, NULL, vpiNoDelay);
}

static void set_signal_long(vpiHandle signal, uint8_t * data)
{
	s_vpi_value value;
	value.format = vpiVectorVal;
	unsigned size = vpi_get(vpiSize, signal);
	unsigned words = (size + 31) / 32;
	value.value.vector =
	    (s_vpi_vecval *) calloc(words, sizeof(s_vpi_vecval));
	int i, j;
	uint32_t datum;
	for (i = 0; i < words; i++) {
		datum = 0;
		for (j = 0; j < 4; j++) {
			datum <<= 8;
			datum += data[i * 4 + j];
		}
		value.value.vector[words - (i + 1)].aval = datum;
	}
	vpi_put_value(signal, &value, NULL, vpiNoDelay);
}

static void get_signal32(vpiHandle signal, uint32_t * data)
{
	s_vpi_value value;
	value.format = vpiIntVal;
	vpi_get_value(signal, &value);
	*data = value.value.integer;
}

static void get_signal64(vpiHandle signal, uint64_t * data)
{
	s_vpi_value value;
	value.format = vpiVectorVal;
	vpi_get_value(signal, &value);
	*data = (uint64_t) value.value.vector[1].aval;
	*data <<= 32;
	*data |=
	    ((uint64_t) value.value.vector[0].aval) & ((uint64_t) 0xffffffffll);
}

static void get_signal_long(vpiHandle signal, uint8_t * data)
{
	s_vpi_value value;
	value.format = vpiVectorVal;
	unsigned size = vpi_get(vpiSize, signal);
	unsigned words = (size + 31) / 32;
	value.value.vector =
	    (s_vpi_vecval *) calloc(words, sizeof(s_vpi_vecval));
	vpi_get_value(signal, &value);
	int i;
	for (i = 0; i < words; i++) {
		int word = value.value.vector[words - (i + 1)].aval;
		int8_t *byte = (int8_t *) & word;
		int j;
		for (j = 0; j < 4; j++) {
			data[(i + 1) * 4 - (j + 1)] = byte[j];
		}
	}
}

//static vpiHandle set_callback_delay(void *func, int delay)
//{
//  s_vpi_time time;
//  time.type = vpiSimTime;
//  time.high = 0;
//  time.low = delay;
//  s_cb_data cb;
//  cb.reason = cbAfterDelay;
//  cb.cb_rtn = func;
//  cb.obj = 0;
//  cb.time = &time;
//  cb.value = 0;
//  cb.index = 0;
//  cb.user_data = 0;
//  return vpi_register_cb(&cb);
//}

static vpiHandle set_callback_signal(void *func, vpiHandle signal)
{
	s_vpi_time time;
	time.type = vpiSimTime;
	time.high = 0;
	time.low = 0;
	s_vpi_value value;
	value.format = vpiIntVal;
	s_cb_data cb;
	cb.reason = cbValueChange;
	cb.cb_rtn = func;
	cb.obj = signal;
	cb.time = &time;
	cb.value = &value;
	cb.index = 0;
	cb.user_data = 0;
	return vpi_register_cb(&cb);
}

static vpiHandle set_callback_event(void *func, int event)
{
	s_cb_data cb;
	cb.reason = event;
	cb.cb_rtn = func;
	cb.obj = 0;
	cb.time = 0;
	cb.value = 0;
	cb.index = 0;
	cb.user_data = 0;
	return vpi_register_cb(&cb);
}

// Helper functions

static void error_message(const char *str)
{
	fflush(stdout);
	fprintf(stderr, "%08lld: ERROR: %s\n", get_time(), str);
	fflush(stderr);
}

static int info_message(char *format, ...)
{
	va_list args;
	int ret;

	printf("%08lld: ", get_time());
	va_start(args, format);
	ret = vprintf(format, args);
	va_end(args);
	return ret;
}

// PSL functions

static void add_response()
{
	struct resp_event *new_resp;
	new_resp = (struct resp_event *)malloc(sizeof(struct resp_event));
	new_resp->tag = event.response_tag;
	new_resp->tagpar = event.response_tag_parity;
	new_resp->code = event.response_code;
	new_resp->credits = event.credits;
	new_resp->__next = NULL;

	event.response_valid = 0;

	if (resp_list == NULL) {
		resp_list = new_resp;
		return;
	}

	struct resp_event *resp_ptr = resp_list;
	while (resp_ptr->__next != NULL)
		resp_ptr = resp_ptr->__next;

	resp_ptr->__next = new_resp;
}

static int test_change(uint32_t previous, uint32_t current, const char *sig)
{

	if (previous != current) {
#ifdef DEBUG
		if (current)
			info_message("%s=%d\n", sig, current);
#endif				/* #ifdef DEBUG */
		return 1;
	}

	return 0;
}

PLI_INT32 aux2()
{
	uint64_t error;
	uint32_t done, running, llcmd_ack, yield, tbreq, paren, lat;
	int change = 0;

	get_signal32(jdone, &done);
	get_signal64(jerror, &error);
	get_signal32(jrunning, &running);
	get_signal32(jcack, &llcmd_ack);
	get_signal32(jyield, &yield);
	get_signal32(timebase_req, &tbreq);
	get_signal32(parity_enabled, &paren);
	get_signal32(latency, &lat);

	change = test_change(event.job_done, done, "jdone");
	if (change && error)
		info_message("jerror=0x%016llx\n", (long long)error);
	change += test_change(event.job_running, running, "jrunning");
	change += test_change(event.job_cack_llcmd, llcmd_ack, "jcack");
	change += test_change(event.job_yield, yield, "jyield");
	change += test_change(event.timebase_request, tbreq, "jtbreq");
	change += test_change(event.parity_enable, paren, "paren");
	change += test_change(event.buffer_read_latency, lat, "brlat");

	if (change)
		psl_afu_aux2_change(&event, running, done, llcmd_ack, error,
				    yield, tbreq, paren, lat);

	return 0;
}

void mmio()
{
	uint64_t data, datapar;
	uint32_t ack;

	get_signal32(mmack, &ack);

	if (!ack)
		return;

	get_signal64(mmrdata, &data);
	get_signal64(mmrdatapar, &datapar);
	psl_afu_mmio_ack(&event, data, datapar);

#ifdef DEBUG
	printf("\n");
	info_message("MMIO Ack data=0x%016llx\n", data);
#endif				/* #ifdef DEBUG */
}

static void command()
{
	uint64_t addr, addrpar;
	uint32_t valid, tag, tagpar, com, compar, abt, size, handle;

	get_signal32(cvalid, &valid);
	if (!valid)
		return;

	get_signal32(ctag, &tag);
	get_signal32(ctagpar, &tagpar);
	get_signal32(ccom, &com);
	get_signal32(ccompar, &compar);
	get_signal32(cabt, &abt);
	get_signal64(cea, &addr);
	get_signal64(ceapar, &addrpar);
	get_signal32(csize, &size);
	get_signal32(cch, &handle);
	psl_afu_command(&event, tag, tagpar, com, compar, addr, addrpar, size,
			abt, handle);

#ifdef DEBUG
	info_message
	    ("Command tag=0x%02x com=%03x ea=0x%016llx size=%d abt=%x\n", tag,
	     com, addr, size, abt);
#endif				/* #ifdef DEBUG */

	return;
}

void buffer_read()
{
	uint32_t tag, valid, parity;
	uint16_t parity16;
	uint8_t data[CACHELINE_BYTES];

	get_signal32(brvalid_out, &valid);

	if (!valid)
		return;

	get_signal32(brtag_out, &tag);
	get_signal_long(brdata, data);
	get_signal32(brpar, &parity);
	parity16 = (uint16_t) parity;
	parity16 = htobe16(parity16);
	psl_afu_read_buffer_data(&event, CACHELINE_BYTES, data,
				 (uint8_t *) & parity16);

#ifdef DEBUG
	info_message("Buffer read data tag=0x%02x", tag);
	unsigned i;
	for (i = 0; i < CACHELINE_BYTES; i++) {
		if (!(i % 32))
			printf("\n  0x");
		printf("%02x", event.buffer_rdata[i]);
	}
	printf("\n");
#endif				/* #ifdef DEBUG */
}

// Clean up on clock edges

PLI_INT32 clock_edge()
{
	uint32_t clock;
	get_signal32(pclock, &clock);

	if (!clock) {
		aux2();
		mmio();
		buffer_read();
		return 0;
	}

	psl();
	command();

	if (cl_jval) {
		--cl_jval;
		if (!cl_jval)
			set_signal32(jval, 0);
	}

	if (cl_mmio) {
		--cl_mmio;
		if (!cl_mmio)
			set_signal32(mmval, 0);
	}

	if (cl_br) {
		--cl_br;
		if (!cl_br)
			set_signal32(brval, 0);
	}

	if (cl_bw) {
		--cl_bw;
		if (!cl_bw)
			set_signal32(bwval, 0);
	}

	if (cl_rval) {
		--cl_rval;
		if (!cl_rval)
			set_signal32(rval, 0);
	}

	return 0;
}

// Setup & facility functions

PLI_INT32 register_clock()
{
	vpiHandle systfref, argsiter;
	systfref = vpi_handle(vpiSysTfCall, NULL);
	argsiter = vpi_iterate(vpiArgument, systfref);

	pclock = vpi_scan(argsiter);
	set_callback_signal(clock_edge, pclock);

	return 0;
}

PLI_INT32 register_control()
{
	vpiHandle systfref, argsiter;
	systfref = vpi_handle(vpiSysTfCall, NULL);
	argsiter = vpi_iterate(vpiArgument, systfref);

	jval = vpi_scan(argsiter);
	jcom = vpi_scan(argsiter);
	jcompar = vpi_scan(argsiter);
	jea = vpi_scan(argsiter);
	jeapar = vpi_scan(argsiter);
	jrunning = vpi_scan(argsiter);
	jdone = vpi_scan(argsiter);
	jcack = vpi_scan(argsiter);
	jerror = vpi_scan(argsiter);
	latency = vpi_scan(argsiter);
	jyield = vpi_scan(argsiter);
	timebase_req = vpi_scan(argsiter);
	parity_enabled = vpi_scan(argsiter);
	cl_jval = 0;

	set_signal32(jval, 0);

	return 0;
}

PLI_INT32 register_mmio()
{
	vpiHandle systfref, argsiter;
	systfref = vpi_handle(vpiSysTfCall, NULL);
	argsiter = vpi_iterate(vpiArgument, systfref);

	mmval = vpi_scan(argsiter);
	mmcfg = vpi_scan(argsiter);
	mmrnw = vpi_scan(argsiter);
	mmdw = vpi_scan(argsiter);
	mmad = vpi_scan(argsiter);
	mmadpar = vpi_scan(argsiter);
	mmwdata = vpi_scan(argsiter);
	mmwdatapar = vpi_scan(argsiter);
	mmack = vpi_scan(argsiter);
	mmrdata = vpi_scan(argsiter);
	mmrdatapar = vpi_scan(argsiter);
	cl_mmio = 0;

	set_signal32(mmval, 0);

	return 0;
}

PLI_INT32 register_command()
{
	vpiHandle systfref, argsiter;
	systfref = vpi_handle(vpiSysTfCall, NULL);
	argsiter = vpi_iterate(vpiArgument, systfref);

	croom = vpi_scan(argsiter);
	cvalid = vpi_scan(argsiter);
	ctag = vpi_scan(argsiter);
	ctagpar = vpi_scan(argsiter);
	ccom = vpi_scan(argsiter);
	ccompar = vpi_scan(argsiter);
	cabt = vpi_scan(argsiter);
	cea = vpi_scan(argsiter);
	ceapar = vpi_scan(argsiter);
	cch = vpi_scan(argsiter);
	csize = vpi_scan(argsiter);

	set_signal32(croom, event.room);

	return 0;
}

PLI_INT32 register_rd_buffer()
{
	vpiHandle systfref, argsiter;
	systfref = vpi_handle(vpiSysTfCall, NULL);
	argsiter = vpi_iterate(vpiArgument, systfref);

	brval = vpi_scan(argsiter);
	brtag = vpi_scan(argsiter);
	brtagpar = vpi_scan(argsiter);
	brdata = vpi_scan(argsiter);
	brpar = vpi_scan(argsiter);
	brvalid_out = vpi_scan(argsiter);
	brtag_out = vpi_scan(argsiter);
	brlat = vpi_scan(argsiter);
	cl_br = 0;

	set_signal32(brval, 0);

	return 0;
}

PLI_INT32 register_wr_buffer()
{
	vpiHandle systfref, argsiter;
	systfref = vpi_handle(vpiSysTfCall, NULL);
	argsiter = vpi_iterate(vpiArgument, systfref);

	bwval = vpi_scan(argsiter);
	bwtag = vpi_scan(argsiter);
	bwtagpar = vpi_scan(argsiter);
	bwdata = vpi_scan(argsiter);
	bwpar = vpi_scan(argsiter);
	cl_bw = 0;

	set_signal32(bwval, 0);

	return 0;
}

PLI_INT32 register_response()
{
	vpiHandle systfref, argsiter;
	systfref = vpi_handle(vpiSysTfCall, NULL);
	argsiter = vpi_iterate(vpiArgument, systfref);

	rval = vpi_scan(argsiter);
	rtag = vpi_scan(argsiter);
	rtagpar = vpi_scan(argsiter);
	resp = vpi_scan(argsiter);
	rcredits = vpi_scan(argsiter);
	cl_rval = 0;

	set_signal32(rval, 0);

	return 0;
}

PLI_INT32 clear_rval()
{
	set_signal32(rval, 0);
	return 0;
}

// AFU abstraction functions

static void set_job()
{
	set_signal32(jcom, event.job_code);
	set_signal32(jcompar, event.job_code_parity);
	set_signal64(jea, event.job_address);
	set_signal32(jeapar, event.job_address_parity);
	set_signal32(jval, 1);

#ifdef DEBUG
	info_message("Job 0x%03x EA=0x%016llx\n", event.job_code,
		     event.job_address);
#endif				/* #ifdef DEBUG */

	cl_jval = CLOCK_EDGE_DELAY;

	event.job_valid = 0;
}

static void set_mmio()
{
	set_signal32(mmrnw, event.mmio_read);
	set_signal32(mmdw, event.mmio_double);
	set_signal64(mmad, event.mmio_address);
	set_signal64(mmadpar, event.mmio_address_parity);
	set_signal64(mmwdata, event.mmio_wdata);
	set_signal64(mmwdatapar, event.mmio_wdata_parity);
	set_signal32(mmcfg, event.mmio_afudescaccess);
	set_signal32(mmval, 1);

#ifdef DEBUG
	info_message("MMIO rnw=%d dw=%d addr=0x%08x data=0x%016llx\n",
		     event.mmio_read, event.mmio_double, event.mmio_address,
		     event.mmio_wdata);
#endif				/* #ifdef DEBUG */

	cl_mmio = CLOCK_EDGE_DELAY;

	event.mmio_valid = 0;
}

static void set_buffer_read()
{
	set_signal32(brtag, event.buffer_read_tag);
	set_signal32(brtagpar, event.buffer_read_tag_parity);
	set_signal32(brval, 1);

#ifdef DEBUG
	info_message("Buffer Read tag=0x%02x\n", event.buffer_read_tag);
#endif				/* #ifdef DEBUG */

	cl_br = CLOCK_EDGE_DELAY;

	event.buffer_read = 0;
}

static void set_buffer_write()
{
	bw_delay += 2;
	uint32_t parity;
	parity = (uint32_t) event.buffer_wparity[0];
	parity <<= 8;
	parity += (uint32_t) event.buffer_wparity[1];

	set_signal32(bwtag, event.buffer_write_tag);
	set_signal32(bwtagpar, event.buffer_write_tag_parity);
	set_signal_long(bwdata, event.buffer_wdata);
	set_signal32(bwpar, parity);
	set_signal32(bwval, 1);

#ifdef DEBUG
	info_message("Buffer Write tag=0x%02x\n", event.buffer_write_tag);
#endif				/* #ifdef DEBUG */

	cl_bw = CLOCK_EDGE_DELAY;

	event.buffer_write = 0;
}

static void set_response()
{
	set_signal32(rtag, resp_list->tag);
	set_signal32(rtagpar, resp_list->tagpar);
	set_signal32(resp, resp_list->code);
	set_signal32(rcredits, resp_list->credits);
	set_signal32(rval, 1);

#ifdef DEBUG
	info_message("Response tag=0x%02x code=0x%02x credits=%d\n",
		     resp_list->tag, resp_list->code, resp_list->credits);
#endif				/* #ifdef DEBUG */

	struct resp_event *tmp;
	tmp = resp_list;
	resp_list = resp_list->__next;
	free(tmp);

	cl_rval = CLOCK_EDGE_DELAY;
}

// AFU functions

static void psl()
{
	// Wait for clock edge from PSL
	fd_set watchset;
	FD_ZERO(&watchset);
	FD_SET(event.sockfd, &watchset);
	select(event.sockfd + 1, &watchset, NULL, NULL, NULL);
	int rc = psl_get_psl_events(&event);
	// No clock edge
	while (!rc) {
		select(event.sockfd + 1, &watchset, NULL, NULL, NULL);
		rc = psl_get_psl_events(&event);
	}
	// Error case
	if (rc < 0) {
		info_message("Socket closed: Ending Simulation.");
#ifdef FINISH
		vpi_control(vpiFinish, 1);
#else
		vpi_control(vpiStop, 1);
#endif
	}
	// Job
	if (event.job_valid)
		set_job();

	// MMIO
	if (event.mmio_valid)
		set_mmio();

	// Buffer read
	if (event.buffer_read)
		set_buffer_read();

	// Buffer write
	if (event.buffer_write)
		set_buffer_write();
	if (bw_delay > 0)
		--bw_delay;
	if (resp_list && !(bw_delay % 2))
		set_response();

	// Response
	if (event.response_valid)
		add_response();

	// Croom
	if (event.aux1_change) {
		set_signal32(croom, event.room);
		event.aux1_change = 0;
	}
}

PLI_INT32 afu_close()
{
	psl_close_afu_event(&event);
	return 0;
}

PLI_INT32 afu_init()
{
	int port = 32768;
	while (psl_serv_afu_event(&event, port) != PSL_SUCCESS) {
		if (port == 65535) {
			error_message("Unable to find open port!");
		}
		++port;
	}
	set_callback_event(afu_close, cbEndOfSimulation);
	return 0;
}

// Register VLI functions

void registerAfuInitSystfs()
{
	s_vpi_systf_data task_data_s;
	p_vpi_systf_data task_data_p = &task_data_s;
	task_data_p->type = vpiSysTask;
	task_data_p->tfname = "$afu_init";
	task_data_p->calltf = afu_init;
	task_data_p->compiletf = 0;
	vpi_register_systf(task_data_p);
}

void registerRegClockSystfs()
{
	s_vpi_systf_data task_data_s;
	p_vpi_systf_data task_data_p = &task_data_s;
	task_data_p->type = vpiSysTask;
	task_data_p->tfname = "$register_clock";
	task_data_p->calltf = register_clock;
	task_data_p->compiletf = 0;
	vpi_register_systf(task_data_p);
}

void registerRegControlSystfs()
{
	s_vpi_systf_data task_data_s;
	p_vpi_systf_data task_data_p = &task_data_s;
	task_data_p->type = vpiSysTask;
	task_data_p->tfname = "$register_control";
	task_data_p->calltf = register_control;
	task_data_p->compiletf = 0;
	vpi_register_systf(task_data_p);
}

void registerRegMmioSystfs()
{
	s_vpi_systf_data task_data_s;
	p_vpi_systf_data task_data_p = &task_data_s;
	task_data_p->type = vpiSysTask;
	task_data_p->tfname = "$register_mmio";
	task_data_p->calltf = register_mmio;
	task_data_p->compiletf = 0;
	vpi_register_systf(task_data_p);
}

void registerRegCommandSystfs()
{
	s_vpi_systf_data task_data_s;
	p_vpi_systf_data task_data_p = &task_data_s;
	task_data_p->type = vpiSysTask;
	task_data_p->tfname = "$register_command";
	task_data_p->calltf = register_command;
	task_data_p->compiletf = 0;
	vpi_register_systf(task_data_p);
}

void registerRegRdBufferSystfs()
{
	s_vpi_systf_data task_data_s;
	p_vpi_systf_data task_data_p = &task_data_s;
	task_data_p->type = vpiSysTask;
	task_data_p->tfname = "$register_rd_buffer";
	task_data_p->calltf = register_rd_buffer;
	task_data_p->compiletf = 0;
	vpi_register_systf(task_data_p);
}

void registerRegWrBufferSystfs()
{
	s_vpi_systf_data task_data_s;
	p_vpi_systf_data task_data_p = &task_data_s;
	task_data_p->type = vpiSysTask;
	task_data_p->tfname = "$register_wr_buffer";
	task_data_p->calltf = register_wr_buffer;
	task_data_p->compiletf = 0;
	vpi_register_systf(task_data_p);
}

void registerRegResponseSystfs()
{
	s_vpi_systf_data task_data_s;
	p_vpi_systf_data task_data_p = &task_data_s;
	task_data_p->type = vpiSysTask;
	task_data_p->tfname = "$register_response";
	task_data_p->calltf = register_response;
	task_data_p->compiletf = 0;
	vpi_register_systf(task_data_p);
}

void (*vlog_startup_routines[]) () = {
	registerAfuInitSystfs, registerRegClockSystfs, registerRegControlSystfs, registerRegMmioSystfs, registerRegCommandSystfs, registerRegRdBufferSystfs, registerRegWrBufferSystfs, registerRegResponseSystfs, 0	// last entry must be 0
};
