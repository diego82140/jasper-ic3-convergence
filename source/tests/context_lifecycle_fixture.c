/* Observer ownership/retirement fixture; no Jasper or proof certificate. */
#include "../src/events.c"
#include <assert.h>
static unsigned char sequence[352],other_sequence[352],configuration[16],jips[3][2048],circuits[2][128];
static char*names[2][24];
static void initialize(struct run_state*s){ds(s);semantic_contract(s);model_epoch_begin(s);emit(s,"init",false,"fixture=1");emit(s,"init_end",false,"fixture=1");model_record(s);}
static struct hook fixture_hooks[4]={{.kind=H_RUN},{.kind=H_BLOCK},{.kind=H_GETSTATS},{.kind=H_VALIDATION}};
static struct observer_activation*push_scope(struct run_state*s,struct hook*h){
 struct observer_activation*a=calloc(1,sizeof *a);assert(a);
 a->hook=h;a->call.state=s;a->generation=s->id;a->kind=-1;a->token=++observer_token;
 a->parent=observer_top;a->call.operation=a->token;a->gum_depth=a->parent?a->parent->gum_depth+1:0;
 a->call.activation_token=a->token;a->call.run_generation=s->id;
 a->validation_active=s->validation_active;a->validation_props=s->validation_props;
 observer_top=a;current=s;
 s->activation_begins++;s->activation_live++;
 emit(s,"invocation_begin",false,"activation=%"PRIu64" parent_activation=%"PRIu64" hook=%s operation=%"PRIu64" gum_depth=%u run_generation=%"PRIu64,a->token,a->parent?a->parent->token:0,kind_names[h->kind],a->call.operation,a->gum_depth,s->id);
 return a;
}
static void abort_attempt(struct run_state*s){
 push_scope(s,&fixture_hooks[0]);observer_abort_top("fixture_native_run_unwind");retire_abandoned_runs();
 assert(!s->live&&!s->detail&&current!=s&&!observer_top);
}
static void finish(struct run_state*s){
 emit(s,"final",true,"result=valid fixture_not_native_proof=1");s->pending_seal=true;completion_tail_begin(s);
 assert(s->live&&s->detail&&s->completion_tail&&!s->sealed);
}
static struct run_state*validation_start(bool outer_run){
 struct run_state*s=get_run((uintptr_t)jips[0],(uintptr_t)sequence);initialize(s);
 if(outer_run)push_scope(s,&fixture_hooks[0]);
 emit(s,"final",true,"result=valid fixture_not_native_proof=1");
 s->await_validation=true;s->final_validation_expected=true;
 push_scope(s,&fixture_hooks[3]);parity_validation_enter(s,(uintptr_t)configuration);
 return s;
}
static void validation_fixture(const char*mode){
 strcpy(P.hash,"e8cbfa93df42061662aaa530125f47d9255ff29b160aa3559d65c706bb24ce1d");
 P.sat_true=0;P.sat_false=1;P.sat_assume=2;
 if(!strcmp(mode,"validation_outcomes")){
  for(int result=0;result<=5;result++){
   struct run_state*s=validation_start(false);
   struct hook solver={.kind=H_SATAFTER,.rva=0xc818a3};GumCpuContext cpu={.rax=(uintptr_t)result};
   parity_validation_stage(s,H_VALBASE);parity_validation_stage(s,H_VALSTEP);
   parity_validation_solver(s,&solver,&cpu,false);
   assert(s->validation_failed==(result==0));assert(s->validation_inconclusive==(result>=3));
   parity_validation_stage(s,H_VALPROPERTY);
   struct invocation call=observer_top->call;parity_validation_leave(s);observer_return(&fixture_hooks[3],&call);
   completion_tail_begin(s);assert(s->completion_tail&&s->final_validation_observed&&!s->final_validation_aborted);
   retire_completed_runs(0,0,true);assert(!s->live&&s->sealed);
  }
  return;
 }
 struct run_state*s=validation_start(!strcmp(mode,"validation_outer_abort"));uint64_t generation=s->id;
 struct invocation call=observer_top->call;
 parity_validation_stage(s,H_VALBASE);parity_validation_stage(s,H_VALSTEP);
 if(!strcmp(mode,"validation_nested_abort")){
  push_scope(s,&fixture_hooks[3]);assert(observer_top->validation_active);
  observer_abort_top("native_handler_unwind");assert(s->await_validation&&!s->final_validation_aborted&&s->activation_live==1);
  parity_validation_stage(s,H_VALPROPERTY);parity_validation_leave(s);observer_return(&fixture_hooks[3],&call);
 }else{
  struct hook solver={.kind=H_SATAFTER,.rva=0xc818a3};GumCpuContext cpu={.rax=5};
  parity_validation_solver(s,&solver,&cpu,false);assert(s->validation_inconclusive&&!s->validation_failed);
  const char*reason=!strcmp(mode,"validation_gum_abort")?"gum_unwind_observed":"native_handler_unwind";
  observer_abort_top(reason);assert(!s->validation_failed);
  if(!strcmp(mode,"validation_gum_abort")){
   assert(s->await_validation&&!s->final_validation_aborted);retire_completed_runs(0,0,true);
   assert(s->validation_missing&&s->sealed&&!s->live);return;
  }
  assert(s->final_validation_aborted&&!s->await_validation&&s->validation_abort_event);
  if(!strcmp(mode,"validation_outer_abort")){
   observer_abort_top("native_handler_unwind");retire_abandoned_runs();
   assert(!s->live&&s->sealed&&s->final_event&&s->observer_errors==1&&!s->completion_tail);return;
  }
  if(!strcmp(mode,"validation_late_return")){
   assert(!observer_matches(&fixture_hooks[3],&call));assert(s->observer_errors==1);
  }
 }
 /* A normal next-entry boundary must start the tail before INIT retires it. */
 begin_ready_completion_tails();assert(s->completion_tail&&!s->activation_live);
 retire_completed_runs((uintptr_t)jips[0],(uintptr_t)sequence,false);assert(!s->live&&s->sealed&&!s->validation_missing);
 struct run_state*next=get_run((uintptr_t)jips[0],(uintptr_t)sequence);assert(next->id!=generation);initialize(next);finish(next);retire_completed_runs(0,0,true);
}
int main(int argc,char**argv){
 gum_init_embedded();disk_only=true;compress_disk=true;frame_chunks_enabled=true;frame_inline_enabled=true;
 capture_identity();P.details=1;P.cube_data=0;P.cube_size=8;
 *(uintptr_t*)sequence=(uintptr_t)configuration;
 *(uintptr_t*)other_sequence=(uintptr_t)configuration;
 for(int i=0;i<2;i++){
  *(uintptr_t*)(jips[i]+64)=(uintptr_t)circuits[i];
  *(uintptr_t*)circuits[i]=(uintptr_t)names[i];*(int*)(circuits[i]+8)=24;
  *(int*)(circuits[i]+16)=8;*(int*)(circuits[i]+20)=8+i*4;*(int*)(circuits[i]+24)=16+i*4;
  names[i][1]=i?"replacement_signal[0]":"abandoned_signal[0]";
 }
 memcpy(jips[2],jips[0],sizeof jips[0]);
 struct run_state*old=get_run((uintptr_t)jips[0],(uintptr_t)sequence);initialize(old);signal_definition(old,1);
 struct run_state*replacement=get_run((uintptr_t)jips[1],(uintptr_t)sequence);initialize(replacement);
 assert(replacement!=old);abort_attempt(old);
 *(uintptr_t*)(jips[0]+64)=0; /* Old owner is no longer a valid naming context. */
 assert(get_run((uintptr_t)jips[1],(uintptr_t)sequence)==replacement);
 assert(find_seq((uintptr_t)sequence)==replacement);
 uint32_t literal=8;capture_vector_data(replacement,(uintptr_t)&literal,1,"jip_formula");
 assert(replacement->read_failures==0);
 /* Repeated abandoned attempts must release native-detail caches/run slots. */
 for(unsigned i=0;i<MAX_RUNS+8;i++){
  *(uintptr_t*)(jips[0]+64)=(uintptr_t)circuits[0];
  old=get_run((uintptr_t)jips[0],(uintptr_t)sequence);assert(old);initialize(old);abort_attempt(old);
  assert(find_seq((uintptr_t)sequence)==replacement);
 }
 /* An outer native scope survives an inner H_RUN abort. Reinitializing the
  * same native pair must allocate a generation without retiring that outer. */
 old=get_run((uintptr_t)jips[0],(uintptr_t)sequence);initialize(old);
 struct observer_activation*outer=push_scope(old,&fixture_hooks[1]);
 struct invocation outer_call=outer->call;
 push_scope(old,&fixture_hooks[0]);observer_abort_top("fixture_inner_run_abort");
 retire_abandoned_runs();assert(old->live&&old->activation_live==1&&old->detail);
 uint64_t old_generation=old->id;
 struct run_state*fresh=get_run((uintptr_t)jips[0],(uintptr_t)sequence);
 assert(fresh!=old&&fresh->id!=old_generation);initialize(fresh);
 assert(lookup_run((uintptr_t)jips[0],(uintptr_t)sequence)==fresh);
 /* Replacement has a different Jip but deliberately the same seq. This
  * ambiguity has no guessed result, even when current points at one owner. */
 if(argc>1&&!strcmp(argv[1],"ambiguous")){
  current=fresh;assert(!find_seq((uintptr_t)sequence));
  unbound_hook(&fixture_hooks[2],0,(uintptr_t)sequence);
  assert(ambiguous_seq_bindings==1&&unbound_hook_calls==1);
 }
 assert(observer_matches(&fixture_hooks[1],&outer_call));
 observer_return(&fixture_hooks[1],&outer_call);retire_abandoned(old,old_generation);
 assert(!old->live&&!old->detail&&fresh->live);
 uint64_t before=instances;assert(!lookup_run((uintptr_t)jips[0]+1,(uintptr_t)sequence));assert(instances==before);
 /* Reuse the now-free slot. A late boundary carrying its old generation
  * must not retire the replacement even when that replacement is aborted. */
 struct run_state*reused=get_run((uintptr_t)jips[2],(uintptr_t)other_sequence);
 assert(reused==old&&reused->id!=old_generation);initialize(reused);
 push_scope(reused,&fixture_hooks[0]);observer_abort_top("fixture_reused_generation_abort");
 retire_abandoned(reused,old_generation);assert(reused->live&&reused->detail);
 retire_abandoned(reused,reused->id);assert(!reused->live&&!reused->detail);
 assert(!lookup_run((uintptr_t)jips[2],(uintptr_t)other_sequence));
 finish(fresh);finish(replacement);
 /* A completed native result retains context for trailing removals. It
  * remains accessible until the next native-init identity boundary. */
 assert(lookup_run((uintptr_t)jips[0],(uintptr_t)sequence)==fresh);
 emit(fresh,"subsumption_result",false,"by_cube_id=0 removed=0 fixture_not_native_proof=1");
 retire_completed_runs((uintptr_t)jips[0],(uintptr_t)sequence,false);
 assert(!fresh->live&&!replacement->live&&!fresh->detail&&!replacement->detail);
 /* Standalone cleanup attribution uses the actual caller's sequence and
  * exact pending-set address. No native vector range is cached or read. */
 struct run_state*pending=get_run((uintptr_t)jips[2],(uintptr_t)other_sequence);initialize(pending);finish(pending);
 struct hook front={.kind=H_FRONTREMOVE,.rva=0x17048e0,.fixed_flags=0};
 strcpy(P.hash,"b5006df1ff1ab23d9effd5eec464b1962a0905da1880aaa8fae574a4a9a81604");
 assert(pending_front_callsite(&front,bias+0x170121b));
 assert(!pending_front_callsite(&front,bias+0x170121c));
 front.fixed_flags=1;assert(!pending_front_callsite(&front,bias+0x170121b));front.fixed_flags=0;
 strcpy(P.hash,"e8cbfa93df42061662aaa530125f47d9255ff29b160aa3559d65c706bb24ce1d");front.rva=0xca6300;
 assert(pending_front_callsite(&front,bias+0xca2bf2));
 assert(!pending_front_callsite(&front,bias+0x170121b));
 P.hash[0]=0;assert(!pending_front_callsite(&front,bias+0xca2bf2));
 assert(pending_front_owner((uintptr_t)other_sequence+152,(uintptr_t)other_sequence)==pending);
 assert(!pending_front_owner((uintptr_t)other_sequence+120,(uintptr_t)other_sequence));
 assert(!pending_front_owner(151,UINTPTR_MAX));
 retire_completed_runs(0,0,true);
 assert(!pending_front_owner((uintptr_t)other_sequence+152,(uintptr_t)other_sequence));
 pending=get_run((uintptr_t)jips[2],(uintptr_t)other_sequence);initialize(pending);
 push_scope(pending,&fixture_hooks[0]);observer_abort_top("fixture_pending_set_after_abort");
 assert(pending->live&&pending->run_unwound);
 assert(!pending_front_owner((uintptr_t)other_sequence+152,(uintptr_t)other_sequence));
 retire_abandoned_runs();assert(!pending->live&&!pending->detail);
 /* Final without validation must neither merge the next initialized attempt
  * nor manufacture observed validation. Close transport as incomplete. */
 if(argc>1&&!strcmp(argv[1],"missing_validation")){
  for(unsigned i=0;i<3;i++){
   struct run_state*waiting=get_run((uintptr_t)jips[0],(uintptr_t)sequence);initialize(waiting);
   emit(waiting,"final",true,"result=valid fixture_not_native_proof=1");
   waiting->await_validation=true;waiting->final_validation_expected=true;uint64_t generation=waiting->id;
   completion_tail_begin(waiting);assert(!waiting->completion_tail);
   assert(retire_completed_runs(i==1?(uintptr_t)jips[1]:(uintptr_t)jips[0],(uintptr_t)sequence,i==2));
   assert(!waiting->live&&!waiting->detail&&waiting->sealed&&waiting->validation_missing);
   struct run_state*next=get_run((uintptr_t)jips[0],(uintptr_t)sequence);assert(next->id!=generation);initialize(next);finish(next);retire_completed_runs(0,0,true);
  }
 }
 if(argc>1&&!strcmp(argv[1],"resumed_search")){
  struct run_state*tail=get_run((uintptr_t)jips[0],(uintptr_t)sequence);initialize(tail);finish(tail);
  assert(!tail_hook_allowed(tail,&fixture_hooks[0]));assert(tail->observer_errors==1);retire_completed_runs(0,0,true);
 }
 if(argc>1&&!strncmp(argv[1],"validation_",11))validation_fixture(argv[1]);
 assert(!dropped_records&&!ledger_failures);close_disk_sinks();write_worker_manifest(true);
 fprintf(stderr,"OWNERSHIP_FIXTURE abandoned=%u outer_return=1 active_pair_reinit=1 generation_guard=1 post_final_tail=1 pending_set_callsite=1 ambiguity=%u stale_owner_reads=0 dropped=0\n",MAX_RUNS+12,argc>1&&!strcmp(argv[1],"ambiguous"));
 return 0;
}
