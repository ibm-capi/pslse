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
#include "svdpi.h"

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

static int cl_jval, cl_mmio, cl_br, cl_bw, cl_rval;
// Added New
        int c_ha_jval;
        int c_ha_jcom;

        uint32_t c_ah_jrunning;
        uint32_t c_ah_jdone;
        uint32_t c_ah_jcack;
	uint64_t c_ah_jerror;
        uint32_t c_ah_brlat;
        uint32_t c_ah_jyield;
        uint32_t c_ah_tbreq;
        uint32_t c_ah_paren;

        uint32_t c_ah_cvalid;
        uint32_t c_ah_ctag;
        uint32_t c_ah_ctagpar;
        uint32_t c_ah_ccom;
        uint32_t c_ah_ccompar;
        uint32_t c_ah_cabt;
        uint64_t c_ah_cea;
        uint32_t c_ah_ceapar;
        uint32_t c_ah_cch;
        uint32_t c_ah_csize;
        uint32_t c_ha_croom;
        uint32_t c_ah_cpagesize;

	uint32_t c_ah_brtag;
	uint32_t c_ah_brvalid;
	uint32_t c_ah_brpar;
	uint16_t parity16;
	uint8_t  c_ah_brdata[CACHELINE_BYTES];

        uint32_t c_ah_mmack;
        uint64_t c_ah_mmrdata;
        uint32_t c_ah_mmrdatapar;
	uint64_t c_sim_time ;
        int      c_sim_error ;

// New PSL9 DMA0 port
	uint32_t c_d0h_dvalid;
	uint32_t c_d0h_req_utag;
	uint32_t c_d0h_req_itag;
	uint32_t c_d0h_dtype;
	uint32_t c_d0h_dsize;
	uint8_t  c_d0h_ddata[CACHELINE_BYTES];
	uint32_t c_d0h_datomic_op;

// Function declaration

static int getMy64Bit(const svLogicVecVal *my64bSignal, uint64_t *conv64bit);
int getMyCacheLine(const svLogicVecVal *myLongSignal, uint8_t myCacheData[]);
void setMyCacheLine(svLogicVecVal *myLongSignal, uint8_t myCacheData[]);
// Dpi eqt of set_signal32
void setDpiSignal32(svLogicVecVal *my32bSignal, uint32_t inData, int size);
static void setDpiSignal64(svLogicVecVal *my64bSignal, uint64_t data);
static void psl_control(void);
/* commenting out unused functions
static void psl(void);
*/
// VPI abstraction functions


static void setDpiSignal64(svLogicVecVal *my64bSignal, uint64_t data)
{
	(my64bSignal+1)->aval = (uint32_t)(data >> 32);
	(my64bSignal+1)->bval = 0x0;
	(my64bSignal)->aval = (uint32_t)(data & 0xffffffff);
	(my64bSignal)->bval = 0x0;
}
/*
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
*/
// Helper functions

void set_simulation_time(const svLogicVecVal *simulationTime)
{
  
   getMy64Bit(simulationTime, &c_sim_time);
//  printf("inside C: time value  = %08lld\n", (long long) c_sim_time);
}

void get_simuation_error(svLogic *simulationError)
{
  *simulationError  = c_sim_error & 0x1;
//  printf("inside C: error value  = %08d\n",  c_sim_error);
}

static void error_message(const char *str)
{
	fflush(stdout);
//	fprintf(stderr, "%08lld: ERROR: %s\n", get_time(), str);
//	Removing the get_time() from the function, since this is a VPI function unsupported on DPI
	fprintf(stderr, "%08lld: ERROR: %s\n", (long long) c_sim_time, str);
	fflush(stderr);
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
	if (current){
	printf("%08lld: ", (long long) c_sim_time);
	printf("%s=%d\n", sig, current);
        }
#endif				/* #ifdef DEBUG */
		return 1;
	}

	return 0;
}

void psl_bfm(const svLogic       ha_pclock, 		// used as pclock on PLI
                   svLogic       *ha_jval_top, 
	     svLogicVecVal       *ha_jcom_top, 	// 8 bits
                   svLogic       *ha_jcompar_top, 
             svLogicVecVal       *ha_jea_top,	// 64 bits
	           svLogic       *ha_jeapar_top,  
             const svLogic       ah_jrunning_top,  
             const svLogic       ah_jdone_top,
	     const svLogic       ah_jcack_top, 
             svLogicVecVal       *ah_jerror_top, 	// 64 bits
             svLogicVecVal       *ah_brlat_top,  	// 4 bits
//             const svLogic       ah_jyield,
	     const svLogic       ah_tbreq_top,  
             const svLogic       ah_paren_top, 
             svLogic             *ha_mmval_top,
             svLogic             *ha_mmcfg_top, 
             svLogic             *ha_mmrnw_top, 
             svLogic             *ha_mmdw_top,
             svLogicVecVal       *ha_mmad_top, 		//24 bits
             svLogic             *ha_mmadpar_top, 
             svLogicVecVal       *ha_mmdata_top, 		// 64 bits
             svLogic             *ha_mmdatapar_top,				
             const svLogic       ah_mmack_top, 
             const svLogicVecVal *ah_mmdata_top, 		// 64 bits
             const svLogic       ah_mmdatapar_top,
             svLogicVecVal       *ha_croom_top,			// 8 bits
             const svLogic       ah_cvalid_top, 
             const svLogicVecVal *ah_ctag_top, 		// 8 bits
             const svLogic       ah_ctagpar_top, 
             const svLogicVecVal *ah_com_top, 		//13 bits
             const svLogic       ah_compar_top, 
             const svLogicVecVal *ah_cabt_top, 		// 3 bits
             const svLogicVecVal *ah_cea_top, 			// 64 bits
             const svLogic       ah_ceapar_top, 
             const svLogicVecVal *ah_cch_top, 		// 16 bits
             const svLogicVecVal *ah_csize_top, 		//12 bits
             const svLogicVecVal *ah_cpagesize_top, 		//4 bits	: TODO - processing of this o/p
             svLogic             *ha_brvalid_top,
             svLogicVecVal       *ha_brtag_top, 		// 8 bits
                   svLogic       *ha_brtagpar_top, 
             const svLogicVecVal *ah_brdata_top, 		// 1024 bits
             const svLogicVecVal *ah_brpar_top, 		// 16 bits
             const svLogic       ah_brvalid_top, 
             const svLogicVecVal *ah_brtag_top,		// 8 bits
             svLogic             *ha_bwvalid_top, 
             svLogicVecVal       *ha_bwtag_top, 		// 8 bits
             svLogic             *ha_bwtagpar_top,
             svLogicVecVal       *ha_bwdata_top, 		// 1024 bits
             svLogicVecVal       *ha_bwpar_top,		// 16 bits
             svLogic             *ha_rvalid_top, 
             svLogicVecVal       *ha_rtag_top, 		// 8 bits
             svLogic             *ha_rtagpar_top,				
             svLogicVecVal       *ha_rditag_top, 		// 9 bits	: TODO - processing of this port
             svLogic             *ha_rditagpar_top,		// : TODO - processing of this port
             svLogicVecVal       *ha_response_top, 		// 8 bits
             svLogicVecVal       *ha_response_ext_top, 		// 8 bits	: TODO - processing of this port
             svLogicVecVal       *ha_rpagesize_top, 		// 4 bits	: TODO - processing of this port
             svLogicVecVal       *ha_rcachestate_top, 		// 2 bits	: PSL9 interface has defined it as unused
             svLogicVecVal       *ha_rcachepos_top, 		// 13 bits	: PSL9 interface has defined it as unused
             svLogicVecVal       *ha_rcredits_top,		// 9 bits	; to be driven to a constant value of 9'h1
	     const svLogic	 d0h_dvalid_top,		// TODO: all the following ports are to be processed
	     const svLogicVecVal *d0h_req_utag_top,		// 10 bits
	     const svLogicVecVal *d0h_req_itag_top,		// 9 bits
	     const svLogicVecVal *d0h_dtype_top,		// 3 bits
	     const svLogicVecVal *d0h_dsize_top,		// 10 bits
	     const svLogicVecVal *d0h_ddata_top,		// 1024 bits
	     const svLogicVecVal *d0h_datomic_op_top,		// 6 bits
	           svLogic       *hd0_sent_utag_valid_top,  
	           svLogicVecVal *hd0_sent_utag_top,  
	           svLogicVecVal *hd0_sent_utag_sts_top,  
	           svLogic       *hd0_cpl_valid_top,  
	           svLogicVecVal *hd0_cpl_utag_top,  
	           svLogicVecVal *hd0_cpl_type_top,  
	           svLogicVecVal *hd0_cpl_size_top,  
	           svLogicVecVal *hd0_cpl_laddr_top,  
	           svLogicVecVal *hd0_cpl_byte_count_top,  
	           svLogicVecVal *hd0_cpl_data_top,  
	     const svLogic	 d1h_dvalid_top,		// TODO: all the following ports are to be processed
	     const svLogicVecVal *d1h_req_utag_top,		// 10 bits
	     const svLogicVecVal *d1h_req_itag_top,		// 9 bits
	     const svLogicVecVal *d1h_dtype_top,		// 3 bits
	     const svLogicVecVal *d1h_dsize_top,		// 10 bits
	     const svLogicVecVal *d1h_ddata_top,		// 1024 bits
	     const svLogicVecVal *d1h_datomic_op_top,		// 6 bits
	           svLogic       *hd1_sent_utag_valid_top,  
	           svLogicVecVal *hd1_sent_utag_top,  
	           svLogicVecVal *hd1_sent_utag_sts_top,  
	           svLogic       *hd1_cpl_valid_top,  
	           svLogicVecVal *hd1_cpl_utag_top,  
	           svLogicVecVal *hd1_cpl_type_top,  
	           svLogicVecVal *hd1_cpl_size_top,  
	           svLogicVecVal *hd1_cpl_laddr_top,  
	           svLogicVecVal *hd1_cpl_byte_count_top,  
	           svLogicVecVal *hd1_cpl_data_top
             )
{
	int change = 0;
	int invalidVal = 0;
	if ( ha_pclock == sv_0 ) {
	// Replication of aux2 method
	  c_ah_jrunning  = (ah_jrunning_top & 0x2) ? 0 : (ah_jrunning_top & 0x1);
          c_ah_jdone     = (ah_jdone_top & 0x2) ? 0 : (ah_jdone_top & 0x1);
          c_ah_jcack     = (ah_jcack_top & 0x2) ? 0 : (ah_jcack_top & 0x1);
          invalidVal = getMy64Bit(ah_jerror_top, &c_ah_jerror);
//          if(invalidVal)
//		printf("jerror has either X or Z value =0x%016llx\n", (long long)c_ah_jerror);
          c_ah_brlat     = ah_brlat_top->aval & 0x3;	// 4 bits	// FIXME: warning says the valid values are only 1 & 3, therefore changing the mask to 0x3
          invalidVal     = ah_brlat_top->bval & 0x3;	
          if(invalidVal)
          {
	    printf("%08lld: ", (long long) c_sim_time);
	    printf("ah_brlat_top has either X or Z value =0x%08llx\n", (long long)c_ah_brlat);
          }
//          c_ah_jyield    = (ah_jyield & 0x2) ? 0 : (ah_jyield & 0x1);
          c_ah_jyield    = 0;
          c_ah_tbreq     = (ah_tbreq_top & 0x2) ? 0 : (ah_tbreq_top & 0x1);
          c_ah_paren     = (ah_paren_top & 0x2) ? 0 : (ah_paren_top & 0x1);
  	  change = test_change(event.job_done, c_ah_jdone, "jdone");
	  if (change && (c_ah_jerror != 0x0))
          {
	     printf("%08lld: ", (long long) c_sim_time);
	     printf("jerror=0x%016llx\n", (long long)c_ah_jerror);
          }
	  change += test_change(event.job_running, c_ah_jrunning, "jrunning");
	  change += test_change(event.job_cack_llcmd, c_ah_jcack, "jcack");
//	  change += test_change(event.job_yield, c_ah_jyield, "jyield");
	  change += test_change(event.timebase_request, c_ah_tbreq, "jtbreq");
	  change += test_change(event.parity_enable, c_ah_paren, "paren");
	  change += test_change(event.buffer_read_latency, c_ah_brlat, "brlat");
	  if (change)
	    psl_afu_aux2_change(&event, c_ah_jrunning, c_ah_jdone, c_ah_jcack, c_ah_jerror,
				    c_ah_jyield, c_ah_tbreq, c_ah_paren, c_ah_brlat);
	// Replication of aux2 method - ends
	// Replication of the mmio method - start
	  c_ah_mmack = (ah_mmack_top & 0x2) ? 0 : (ah_mmack_top & 0x1);
	  if(c_ah_mmack)
          {
            invalidVal = getMy64Bit(ah_mmdata_top, &c_ah_mmrdata);
            if(invalidVal)
            {
	      printf("%08lld: ", (long long) c_sim_time);
	      printf("ah_mmdata has either X or Z value =0x%016llx\n", (long long)c_ah_mmrdata);
            }
            c_ah_mmrdatapar = (ah_mmdatapar_top & 0x2) ? 0 : (ah_mmdatapar_top & 0x1);
            psl_afu_mmio_ack(&event, c_ah_mmrdata, c_ah_mmrdatapar);
          }
	// Replication of the mmio method - ends
	// Replication of buffer_read method - start
	  change = 0;
	  c_ah_brvalid  = (ah_brvalid_top & 0x2) ? 0 : (ah_brvalid_top & 0x1);
          if(c_ah_brvalid == sv_1)
          {
//	    printf("Command Valid: ah_brvalid=%d\n", c_ah_brvalid);
            c_ah_brtag    = (ah_brtag_top->aval) & 0xFF;	// 8 bits
            invalidVal     = ah_brtag_top->bval & 0xFF;	
            if(invalidVal)
            {
	      printf("%08lld: ", (long long) c_sim_time);
	      printf("ah_brtag_top has either X or Z value =0x%08llx\n", (long long)c_ah_brtag);
            }
            c_ah_brpar    = (ah_brpar_top->aval) & 0xFFFF;	// 16 bits
            invalidVal     = ah_brpar_top->bval & 0xFF;	
            if(invalidVal)
            {
	      printf("%08lld: ", (long long) c_sim_time);
	      printf("ah_brpar_top has either X or Z value =0x%08llx\n", (long long)c_ah_brpar);
            }
	    uint16_t parity16;
	    parity16 = (uint16_t) c_ah_brpar;
	    parity16 = htons(parity16);		
            getMyCacheLine(ah_brdata_top, c_ah_brdata);
	    psl_afu_read_buffer_data(&event, CACHELINE_BYTES, c_ah_brdata,
				 (uint8_t *) & parity16);
	// Replication of buffer_read method - ends
	  }
	// PSL9 handling of DMA port0
	   c_d0h_dvalid = (d0h_dvalid_top & 0x2) ? 0 : (d0h_dvalid_top & 0x1);
	   if(c_d0h_dvalid == sv_1)
	   {
	     c_d0h_req_utag	= (d0h_req_utag_top->aval) 	& 0x3FF;	// 10 bits;
	     c_d0h_req_itag	= (d0h_req_itag_top->aval) 	& 0x1FF;	// 9 bits;
	     c_d0h_dtype	= (d0h_dtype_top->aval) 	& 0x7;		// 3 bits;
	     c_d0h_dsize	= (d0h_dsize_top->aval) 	& 0x3FF;	// 10 bits;
             getMyCacheLine(d0h_ddata_top, c_d0h_ddata);
	     c_d0h_datomic_op	= (d0h_datomic_op_top->aval) 	& 0x3FF;	// 10 bits;
	     psl_afu_dma0_req(&event, c_d0h_req_utag, c_d0h_req_itag, c_d0h_dtype, c_d0h_dsize, c_d0h_datomic_op, c_d0h_ddata);
	   }
	} else {
	  //psl();	// the psl() function from PLI is going to be split into several subsidiary functions
 	  c_sim_error = 0;
	  psl_control();
	// Job
	if (event.job_valid)
	{
	  // replicating set_job() function
          setDpiSignal32(ha_jcom_top, event.job_code, 8);
          *ha_jcompar_top  = (event.job_code_parity) & 0x1;
	  setDpiSignal64(ha_jea_top, event.job_address);
	  *ha_jeapar_top  = (event.job_address_parity) & 0x1;
	  *ha_jval_top = 1;
	  printf("%08lld: ", (long long) c_sim_time);
	  printf("Job 0x%03x EA=0x%016llx\n", event.job_code, (long long)event.job_address);
	  cl_jval = CLOCK_EDGE_DELAY;
	  event.job_valid = 0;
        }	
	// MMIO
	if (event.mmio_valid)
	{
	// replicating the set_mmio() function
	  *ha_mmrnw_top = event.mmio_read;
	  *ha_mmdw_top = event.mmio_double;
	  setDpiSignal32(ha_mmad_top, event.mmio_address, 24);
	  *ha_mmadpar_top = event.mmio_address_parity;
	  setDpiSignal64(ha_mmdata_top, event.mmio_wdata);
	  *ha_mmdatapar_top = (event.mmio_wdata_parity) & 0x1;		// 2016/05/11: UMA: checking whether ensuring bval is set always to 0b0 solves the MMIO parity error which is coming up
	  *ha_mmcfg_top = event.mmio_afudescaccess;
	  *ha_mmval_top = 1;
	  printf("%08lld: ", (long long) c_sim_time);
	  printf("MMIO rnw=%d dw=%d addr=0x%08x data=0x%016llx\n",
		     event.mmio_read, event.mmio_double, event.mmio_address,
		     (long long)event.mmio_wdata);
	  cl_mmio = CLOCK_EDGE_DELAY;
	  event.mmio_valid = 0;
        }
	// Buffer read
	if (event.buffer_read)
	{
	// Replicating	set_buffer_read() function
	  setDpiSignal32(ha_brtag_top, event.buffer_read_tag, 8);
	  *ha_brtagpar_top = event.buffer_read_tag_parity;
	  *ha_brvalid_top = 1;
	  printf("%08lld: ", (long long) c_sim_time);
	  printf("Buffer Read tag=0x%02x\n", event.buffer_read_tag);
	  cl_br = CLOCK_EDGE_DELAY;
	  event.buffer_read = 0;
        }
        else if(!cl_br)
	{	// TODO: check whether this is really causing any issues
	  setDpiSignal32(ha_brtag_top, 0, 8);
	  *ha_brtagpar_top = 0;
        }
	// Buffer write
	if (event.buffer_write)
	{
	// Replicating 	set_buffer_write() function
	  bw_delay += 2;
	  uint32_t parity;
	  parity = (uint32_t) event.buffer_wparity[0];
	  parity <<= 8;
	  parity += (uint32_t) event.buffer_wparity[1];
          // parity = htons((uint16_t) parity);  // we don't need to do this as we processed parity byte-wise rather than as an int
	  setDpiSignal32(ha_bwtag_top, event.buffer_write_tag, 8);
	  *ha_bwtagpar_top = event.buffer_write_tag_parity;
	  setMyCacheLine(ha_bwdata_top, event.buffer_wdata);
	  setDpiSignal32(ha_bwpar_top, parity, 16);
	  *ha_bwvalid_top = 1;
	  printf("%08lld: ", (long long) c_sim_time);
	  printf("Buffer Write tag=0x%02x\n", event.buffer_write_tag);
	  cl_bw = CLOCK_EDGE_DELAY;
	  event.buffer_write = 0;
	}
        else if(!cl_bw)
	{	// TODO: check whether this is really causing any issues
	  setMyCacheLine(ha_bwdata_top, c_ah_brdata);
	  setDpiSignal32(ha_bwpar_top, 0, 16);
        }
	if (bw_delay > 0)
		--bw_delay;
	// ------Driving some blank value as of now
	  setDpiSignal32(ha_rcachestate_top, 0x000,  2);
	  setDpiSignal32(ha_rcachepos_top,   0x000, 13);
	if (resp_list && !(bw_delay % 2))
        {
	// Replicating	set_response() function
	  setDpiSignal32(ha_rtag_top, resp_list->tag, 8);
	  *ha_rtagpar_top = resp_list->tagpar;
	  setDpiSignal32(ha_response_top, resp_list->code, 8);
	// TODO: we can check whether the ha_rcredits are always driven to 9'h1
//	  setDpiSignal32(ha_rcredits_top, resp_list->credits, 9);
	  setDpiSignal32(ha_rcredits_top, 0x001, 9);
	// TODO: add code to handle ha_response_ext_top, ha_rpagesize_top, ha_rcachestate_top, ha_rcachepos_top
	  *ha_rvalid_top = 1;
	  printf("%08lld: ", (long long) c_sim_time);
	  printf("Response tag=0x%02x code=0x%02x credits=%d\n",
		     resp_list->tag, resp_list->code, resp_list->credits);
	  struct resp_event *tmp;
	  tmp = resp_list;
	  resp_list = resp_list->__next;
	  free(tmp);
	  cl_rval = CLOCK_EDGE_DELAY;
        }
	if (resp_list && !(bw_delay % 2))
        {
	  setDpiSignal32(ha_rditag_top, 0x000, 9);
	  *ha_rditagpar_top = 0;
	  setDpiSignal32(ha_rtag_top, 0, 8);
	  *ha_rtagpar_top = 0;
	  setDpiSignal32(ha_response_top, 0, 8);
	  setDpiSignal32(ha_rpagesize_top, 0, 4);
        }
	// Response
	if (event.response_valid)
        {
	// Not Replicating	add_response() function, just calling it
		add_response();
        }
	// Croom
	if (event.aux1_change) {
		setDpiSignal32(ha_croom_top, event.room, 8);
		event.aux1_change = 0;
	}
	// Replication of acceleartor command interface starts
	  c_ah_cvalid = (ah_cvalid_top & 0x2) ? 0 : (ah_cvalid_top & 0x1);
	  if(c_ah_cvalid == sv_1) 
	  {
	    c_ah_ctag    = (ah_ctag_top->aval) & 0xFF;	// 8 bits
	    c_ah_ctagpar = (ah_ctagpar_top & 0x2) ? 0 : (ah_ctagpar_top & 0x1);
	    c_ah_ccompar = (ah_compar_top & 0x2) ? 0 : (ah_compar_top & 0x1);
	    c_ah_ccom    = (ah_com_top->aval) & 0x1FFF;	// 13 bits
            invalidVal = getMy64Bit(ah_cea_top, &c_ah_cea);
            if(invalidVal)
            {
	        printf("%08lld: ", (long long) c_sim_time);
		printf("ah_cea has either X or Z value =0x%016llx\n", (long long)c_ah_cea);
            }
	    c_ah_ceapar  = (ah_ceapar_top & 0x2) ? 0 : (ah_ceapar_top & 0x1);
	    c_ah_csize   = (ah_csize_top->aval) & 0xFFF;	// 12 bits
	    c_ah_cabt    = (ah_cabt_top->aval) & 0x7;		// 3 bits
	    c_ah_cch     = (ah_cch_top->aval) & 0xFFFF;		// 16 bits
	    c_ha_croom   = (ha_croom_top->aval) & 0xFF;		// 8 bits
	    c_ah_cpagesize     = (ah_cpagesize_top->aval) & 0xF;		// 4 bits
		// FIXME: Need to check how to handle Croom on the event structure
	    printf("%08lld: ", (long long) c_sim_time);
	    printf("Command Valid: ccom=0x%x\n", c_ah_ccom);
  	    event.room   = c_ha_croom;
  	    psl_afu_command(&event, c_ah_ctag, c_ah_ctagpar, c_ah_ccom, c_ah_ccompar, c_ah_cea, c_ah_ceapar, c_ah_csize,
	 		   c_ah_cabt, c_ah_cch);
	  }
	  // Replication of acceleartor command interface ends
	  // NEW PSL9 function ------------------ DMA0 port CMPL handling -------------
	  if(event.dma0_completion_valid)			// must be corresponding to the assertion of HDx_CPL_VALID by PSL
	  {
	    setDpiSignal32(hd0_cpl_utag_top, event.dma0_completion_utag, 10);
	    setDpiSignal32(hd0_cpl_type_top, event.dma0_completion_type,  3);
	    setDpiSignal32(hd0_cpl_size_top, event.dma0_completion_size, 12);
	    setMyCacheLine(hd0_cpl_data_top, event.dma0_completion_data);
	    setDpiSignal32(hd0_cpl_laddr_top, 	  event.dma0_completion_laddr, 	10);
	    setDpiSignal32(hd0_cpl_byte_count_top, 	  event.dma0_completion_byte_count, 	10);
	    *hd0_cpl_valid_top = 1;
	  }
	  if(event.dma0_sent_utag_valid)			// must be corresponding to the assertion of HDx_SENT_UTAG_VALID by PSL
	  {
	    setDpiSignal32(hd0_sent_utag_top, 	  event.dma0_sent_utag, 	10);
	    setDpiSignal32(hd0_sent_utag_sts_top, event.dma0_sent_utag_status,   2);
	    *hd0_sent_utag_valid_top = 1;
	  }
	  // Copying over the rest of the assignments from the clock_edge function
	  if (cl_jval) {
	  	--cl_jval;
	  	if (!cl_jval)
	  		*ha_jval_top = 0;
	  }
	  if (cl_mmio) {
	  	--cl_mmio;
	  	if (!cl_mmio)
	  		*ha_mmval_top = 0;
	  }
	  if (cl_br) {
	  	--cl_br;
	  	if (!cl_br)
	  		*ha_brvalid_top = 0;
	  }
	  if (cl_bw) {
	  	--cl_bw;
	  	if (!cl_bw)
	  		*ha_bwvalid_top = 0;
	  }
	  if (cl_rval) {
	  	--cl_rval;
	  	if (!cl_rval)
	  		*ha_rvalid_top = 0;
	  }
	  return;
        }
}

// Setup & facility functions
static int getMy64Bit(const svLogicVecVal *my64bSignal, uint64_t *conv64bit)
{
    //gets the two 32bit values from the 4-state svLogicVec array
    //and packs it into a 64bit in *conv64bit
    //Also returns 1 if bval is non-zero (i.e. value contains Z, X or both)

  uint32_t lsb32_aval, msb32_aval, lsb32_bval, msb32_bval;
  lsb32_bval =  my64bSignal->bval;
  msb32_bval = (my64bSignal+1)->bval;
  lsb32_aval =  my64bSignal->aval;
  msb32_aval = (my64bSignal+1)->aval;
//    printf("msb32_aval=%08x, lsb32_aval=%08x\n", msb32_aval, lsb32_aval); 
//    printf("msb32_bval=%08x, lsb32_bval=%08x\n", msb32_bval, lsb32_bval); 
 
  *conv64bit = ((uint64_t) msb32_aval <<32) | (uint64_t) lsb32_aval;
//    printf("conv64bit = %llx\n", (long long) *conv64bit);
  if((lsb32_bval | msb32_bval) == 0){ return 0;}
  return 1;
}

// The getMyCacheLine is a more specific version of the PLI function
// get_signal_long. In here, we are specifically doing the conversion of 1024
// bit long vector to 128 byte cacheline buffer. On VPI as well as DPI, the
// 1024 bit vector is returned as array of 32bit entries. ie, array[0] will
// contain the aval for bits [992:1023]. The PSLSE demands that the first
// entry of the array has bits [0:31], hence we do a reversal of that array
// the htonl std lib function will ensure that the byte ordering is maintained
// based on the endianness of the processor
int getMyCacheLine(const svLogicVecVal *myLongSignal, uint8_t myCacheData[CACHELINE_BYTES])
{
   int i, j;
  //uint32_t get32aval, get32bval;
  uint8_t errorVal = 0;
  uint32_t *p32BitCacheWords = (uint32_t*)myCacheData;
  for(i=0; i <(CACHELINE_BYTES/4 ); i++)
  {
    j = (CACHELINE_BYTES/4 ) - (i + 1);
    if(myLongSignal[i].bval !=0){ errorVal=1; }
    p32BitCacheWords[j] = myLongSignal[i].aval; 
    p32BitCacheWords[j] = htonl(p32BitCacheWords[j]);
  }
  if(errorVal!=0){return 1;}
  return 0;
}

void setMyCacheLine(svLogicVecVal *myLongSignal, uint8_t myCacheData[CACHELINE_BYTES])
{
   int i, j;
  //uint32_t get32aval, get32bval;
  uint32_t *p32BitCacheWords = (uint32_t*)myCacheData;
  for(i=0; i <(CACHELINE_BYTES/4 ); i++)
  {
    j = (CACHELINE_BYTES/4 ) - (i + 1);
    myLongSignal[j].aval = htonl(p32BitCacheWords[i]); 
    myLongSignal[j].bval = 0;
  }
}

void setDpiSignal32(svLogicVecVal *my32bSignal, uint32_t inData, int size)
{
  uint32_t myMask = ~(0xFFFFFFFF << size);
  my32bSignal->aval = inData & myMask;
  my32bSignal->bval = 0x0;
}

// AFU abstraction functions

// AFU functions
/*
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
*/
static void psl_control(void)
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
	  printf("%08lld: ", (long long) c_sim_time);
	  printf("Socket closed: Ending Simulation.");
	  c_sim_error = 1;
	}
}

void psl_bfm_init()
{
  int port = 32768;
  while (psl_serv_afu_event(&event, port) != PSL_SUCCESS) {
    if (psl_serv_afu_event(&event, port) == PSL_VERSION_ERROR) {
      printf("%08lld: ", (long long) c_sim_time);
      printf("Socket closed: Ending Simulation.");
      c_sim_error = 1;
    }
    if (port == 65535) {
      error_message("Unable to find open port!");
    }
    ++port;
  }
  // set_callback_event(afu_close, cbEndOfSimulation);
  return;
}


