/* Real collector routines on synthetic native layouts; never a Jasper proof. */
#include "../src/events.c"
#include <assert.h>
struct fixture_cube {uintptr_t data;int size,capacity;};
struct fixture_po {uint32_t flags;int cex_size;uintptr_t cube,parent;};
static unsigned char sequence[352],jip[2048],circuit[128],configuration[64];
static char*names[24];
static uint32_t literals[2]={2,4};
static struct fixture_cube cube={(uintptr_t)literals,2,2};
static struct fixture_po obligations_fixture[20];
int main(int argc,char**argv){
 assert(argc==2);gum_init_embedded();disk_only=true;compress_disk=true;frame_chunks_enabled=true;frame_inline_enabled=true;
 capture_identity();P.details=1;P.cube_data=0;P.cube_size=8;P.rel_true=1;P.rel_false=-1;P.sat_false=1;P.sat_assume=2;
 P.k_offset=200;P.obligations_offset=280;P.pre_bad_offset=272;P.pre_other_offset=276;P.generalize_offset=284;P.calls_offset=288;
 const char*sha=getenv("JIPSTATS_FIXTURE_WORKER_SHA");assert(sha&&strlen(sha)==64);strcpy(P.hash,sha);
 *(uintptr_t*)sequence=(uintptr_t)configuration;*(uintptr_t*)(jip+64)=(uintptr_t)circuit;
 *(uintptr_t*)circuit=(uintptr_t)names;*(int*)(circuit+8)=24;*(int*)(circuit+16)=8;*(int*)(circuit+20)=8;*(int*)(circuit+24)=16;
 names[0]="edge_input";names[1]="~edge_state[0]";
 bool retained=!strcmp(argv[1],"retained");
 if(retained){P.details=0;strcpy(P.hash,"690e3ca961c62999509196ddb8a7f94a1707c6b129fa6f392f25b038206dad47");}
 struct run_state*s=&runs[0];s->id=1;s->live=true;s->seq=(uintptr_t)sequence;s->jip=(uintptr_t)jip;
 register_run(s);struct detailed_state*d=ds(s);semantic_contract(s);model_epoch_begin(s);model_record(s);
 if(retained){signal_definition(s,1);}
 else if(!strcmp(argv[1],"invalid_read")){
  assert(!full_cube(s,1));assert(s->read_failures>0);
 }else{
  for(int i=0;i<20;i++)obligations_fixture[i]=(struct fixture_po){(uint32_t)(i<<2),20-i,(uintptr_t)&cube,i==19?0:(uintptr_t)&obligations_fixture[i+1]};
  obligations_fixture[3].flags=0xffffffffU;
  uint64_t head=record_obligation_cex_chain(s,(uintptr_t)obligations_fixture);
  assert(head&&d->po_ids==20&&g_hash_table_size(d->pos)==20);
  /* The real before-call probe opens an unknown-result-free SAT invocation. */
  uintptr_t vtable[20]={0},solver=(uintptr_t)vtable;*(uintptr_t*)(sequence+72)=(uintptr_t)&solver;
  uintptr_t assumptions[3]={(uintptr_t)literals,(uintptr_t)(literals+2),(uintptr_t)(literals+2)};
  struct hook site={.kind=H_SATBEFORE,.rva=0x1234};
  GumCpuContext cpu={.rdi=(uintptr_t)&solver,.rax=(uintptr_t)vtable,.rsi=(uintptr_t)assumptions,.rsp=(uintptr_t)&cpu,.rdx=(uintptr_t)-1};
  d->relative_cube=(uintptr_t)&cube;
  struct hook run_hook={.kind=H_RUN};struct observer_activation*owner=calloc(1,sizeof *owner);assert(owner);
  owner->hook=&run_hook;owner->generation=s->id;owner->token=7;owner->kind=-1;owner->call.state=s;
  owner->call.activation_token=7;owner->call.run_generation=s->id;owner->call.operation=7;
  observer_top=owner;current=s;s->activation_begins=1;s->activation_live=1;
  emit(s,"invocation_begin",false,"activation=7 parent_activation=0 hook=run operation=7 gum_depth=0 run_generation=1");
  sat_call_probe(s,&site,&cpu,true,7);assert(d->sat_depth==1);
  observer_sat_abort(s,7,"fixture_native_cancel");assert(!d->sat_depth&&active_queries==0);
  struct invocation call=owner->call;observer_return(&run_hook,&call);assert(!s->activation_live);
 }
 emit(s,"final",true,"result=cex fixture_not_native_proof=1");semantic_seal(s);
 close_disk_sinks();write_worker_manifest(true);return 0;
}
