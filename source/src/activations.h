/* Experimental lifecycle recovery with explicit phase-2 aborts. The patched
 * interceptor restores native return slots before unwinding; release-level
 * Jasper qualification is separate. Depth-only reaping fails at sibling sites.
 * Own only live activation copies: Gum invocation storage can be recycled.
 * Depth follows the pinned interceptor contract, not a guessed native SP rule.
 */
struct observer_activation {
 struct observer_activation *parent;
 struct hook *hook;
 struct invocation call;
 uint64_t token,generation,previous_generation,relative,operation,generalization;
 unsigned gum_depth,relative_depth,push_depth,add_depth;
 int kind,relative_frame,relative_flags;
 uintptr_t relative_cube,heap,validation_props;
 uintptr_t function,entry_stack,return_address;
 uint64_t listeners[(MAX_HOOKS+63)/64];
 bool validation_active;
};
static _Thread_local struct observer_activation *observer_top;
static _Thread_local uint64_t observer_token;

static void observer_anomaly(struct run_state*s,uint64_t generation,const char*reason){
 if(s&&s->live&&s->id==generation){
  s->observer_errors++;
  emit(s,"observer_error",true,"reason=%s native_return_inferred=0",reason);
 }else __atomic_add_fetch(&ledger_failures,1,__ATOMIC_RELAXED);
}
static uint64_t observer_current_token(struct run_state*s){
 for(struct observer_activation*a=observer_top;a;a=a->parent)
  if(a->call.state==s&&a->generation==s->id)return a->token;
 return 0;
}
static void observer_sat_abort(struct run_state*s,uint64_t owner,const char*reason){
 struct detailed_state*d=s->detail;if(!d)return;
 while(d->sat_depth&&d->sat_stack[d->sat_depth-1].owner==owner){
  struct sat_inflight*v=&d->sat_stack[--d->sat_depth];
  emit(s,"sat_abort",false,"call=%"PRIu64" relative_query=%"PRIu64" activation=%"PRIu64" native_callsite=%"PRIxPTR" reason=%s native_return_observed=0",v->id,v->query,owner,v->site,reason);
  __atomic_sub_fetch(&active_queries,1,__ATOMIC_RELAXED);
 }
}
static void observer_restore(struct observer_activation*a,bool aborted){
 struct run_state*s=a->call.state;
 if(s->id==a->generation&&s->live){
  struct detailed_state*d=s->detail;
  s->current_operation=a->operation;s->current_kind=a->kind;
  switch(a->hook->kind){
  case H_RELATIVE:
   s->rel_depth=a->relative_depth;s->current_relative=a->relative;
   if(d){d->relative_frame=a->relative_frame;d->relative_flags=a->relative_flags;d->relative_cube=a->relative_cube;}break;
  case H_PUSH:if(d)d->push_depth=a->push_depth;break;
  case H_ADDCUBE:if(d)d->add_depth=a->add_depth;break;
  case H_GENERALIZE:if(d)d->current_generalize=a->generalization;break;
  case H_BLOCK:case H_OBLIGATION:if(d)d->heap=a->heap;break;
  case H_VALIDATION:
   s->validation_active=a->validation_active;s->validation_props=a->validation_props;
   if(aborted)s->validation_inconclusive=true;
   break;
  default:break;
  }
 }
 struct run_state*previous=a->call.previous;
 current=previous&&previous->live&&previous->id==a->previous_generation?previous:NULL;
}
static void observer_abort_top(const char*reason){
 struct observer_activation*a=observer_top;struct run_state*s=a->call.state;
 if(s->live&&s->id==a->generation){
  observer_sat_abort(s,a->token,reason);
  if(a->hook->kind==H_RELATIVE&&!a->call.suppressed){
   emit(s,"query_abort",false,"query=%"PRIu64" operation=%"PRIu64" activation=%"PRIu64" frame=%d reason=%s native_return_observed=0 output_cube_inferred=0",a->call.id,a->call.operation,a->token,a->call.frame,reason);
   __atomic_sub_fetch(&active_queries,1,__ATOMIC_RELAXED);
  }else if(a->hook->kind==H_SAT){
   emit(s,"sat_abort",false,"call=%"PRIu64" relative_query=%"PRIu64" activation=%"PRIu64" reason=%s native_return_observed=0",a->call.id,a->call.previous_relative,a->token,reason);
   __atomic_sub_fetch(&active_queries,1,__ATOMIC_RELAXED);
  }
  emit(s,"invocation_abort",false,"activation=%"PRIu64" hook=%s operation=%"PRIu64" query=%"PRIu64" gum_depth=%u reason=%s native_return_observed=0",a->token,kind_names[a->hook->kind],a->call.operation,a->call.id,a->gum_depth,reason);
  if(a->hook->kind==H_RUN){s->run_unwound=true;s->run_abort_event=s->records;model_context_observe(s,"run_abort",0);}
  if(a->hook->kind==H_VALIDATION&&!a->validation_active&&s->await_validation&&s->final_validation_expected&&s->final_event&&!strcmp(reason,"native_handler_unwind")){
   s->final_validation_aborted=true;s->validation_abort_event=s->records;
   s->await_validation=false;s->pending_seal=true;
  }
  if(a->call.semantic_scope)
   emit(s,"operation_abort",false,"operation=%"PRIu64" parent_operation=%"PRIu64" kind=%s entry_revision=%"PRIu64" exit_revision=%"PRIu64" reason=%s native_return_observed=0",a->call.operation,a->call.parent_operation,kind_names[a->hook->kind],a->call.entry_revision,s->context_revision,reason);
  s->activation_aborts++;s->activation_live--;
 }else observer_anomaly(s,a->generation,"abandoned_run_generation_mismatch");
 observer_restore(a,true);observer_top=a->parent;free(a);
 /* File-backed terminal/retirement is deferred to a normal hook boundary or
  * process finalization, outside the personality listener. */
}
static void observer_reconcile(unsigned depth,bool leaving){
 while(observer_top&&(leaving?observer_top->gum_depth>depth:observer_top->gum_depth>=depth)){
  observer_anomaly(observer_top->call.state,observer_top->generation,"unexplained_native_scope_exit");
  observer_abort_top("gum_unwind_observed");
 }
}
/* x86-64 SysV: the handler's unwinder context identifies its live call-site
 * stack boundary. A callee's entry return slot lies below that boundary.
 * The handler context comes from the actual phase-2
 * unwinder, not from the SP of a later, unrelated callback. Gum's broker
 * still owns PC translation and native resume; this listener changes neither.
 */
static uintptr_t (*observer_get_cfa)(void*);
static GumInvocationListener *observer_personality_listener,*observer_jump_listener;
static void observer_jump_enter(GumInvocationContext*ctx,gpointer unused){
 (void)ctx;(void)unused;int saved=errno;
 /* A jump buffer's destination is opaque. Restore native execution and close
  * every observed scope without inferring which activation survives. */
 while(observer_top){
  observer_anomaly(observer_top->call.state,observer_top->generation,"nonlocal_jump_scope_coverage_lost");
  observer_abort_top("native_nonlocal_jump");
 }
 errno=saved;
}
struct observer_personality_call {uintptr_t cfa;unsigned actions;};
static void observer_personality_enter(GumInvocationContext*ctx,gpointer unused){
 (void)unused;int saved=errno;
 struct observer_personality_call*v=gum_invocation_context_get_listener_invocation_data(ctx,sizeof *v);
 v->actions=(unsigned)(uintptr_t)gum_invocation_context_get_nth_argument(ctx,1);
 v->cfa=observer_get_cfa(gum_invocation_context_get_nth_argument(ctx,4));
 errno=saved;
}
static void observer_personality_leave(GumInvocationContext*ctx,gpointer unused){
 (void)unused;int saved=errno;
 struct observer_personality_call*v=gum_invocation_context_get_listener_invocation_data(ctx,sizeof *v);
 /* All phase-2 landing pads, including destructor cleanup before a catch. */
 if((v->actions&2)&&(uintptr_t)gum_invocation_context_get_return_value(ctx)==7){
  if(!v->cfa){if(observer_top)observer_anomaly(observer_top->call.state,observer_top->generation,"unwind_handler_CFA_unavailable");}
  else while(observer_top&&observer_top->entry_stack<v->cfa){
   struct observer_activation*a=observer_top;
   if(a->call.state->live&&a->call.state->id==a->generation){
    a->call.state->native_unwind_aborts++;
    emit(a->call.state,"unwind_handler",false,"activation=%"PRIu64" native_handler_cfa=%"PRIxPTR" native_activation_cfa=%"PRIxPTR" actions=%u native_resume_preserved=1",a->token,v->cfa,a->entry_stack+8,v->actions);
   }else observer_anomaly(a->call.state,a->generation,"unwind_landing_generation_mismatch");
   observer_abort_top("native_handler_unwind");
  }
 }
 errno=saved;
}
static bool observer_listener_alias(GumInvocationContext*ctx,struct hook*h){
 struct observer_activation*a=observer_top;if(!a)return false;
 unsigned listener=(unsigned)(h-P.hooks);
 if(listener>=P.nh||!a->call.state->live||a->call.state->id!=a->generation||(a->listeners[listener/64]&(UINT64_C(1)<<(listener%64))))return false;
 if(a->gum_depth!=gum_invocation_context_get_depth(ctx)||a->hook==h||a->function!=(uintptr_t)ctx->function||a->entry_stack!=ctx->cpu_context->rsp||a->return_address!=(uintptr_t)gum_invocation_context_get_return_address(ctx))return false;
 /* Gum resolves an unconditional entry JMP. Several profile locations can
  * consequently attach listeners to one frame, in installation order. */
 struct hook*p=a->hook;
 if(p->kind!=h->kind||p->jip_arg!=h->jip_arg||p->seq_arg!=h->seq_arg||p->frame_arg!=h->frame_arg||p->flags_arg!=h->flags_arg||p->cube_arg!=h->cube_arg||p->fixed_flags!=h->fixed_flags){
  observer_anomaly(a->call.state,a->generation,"resolved_listener_alias_ABI_conflict");
 }else emit(a->call.state,"listener_alias",false,"activation=%"PRIu64" native_entry=%"PRIxPTR" canonical_entry=%"PRIxPTR" resolved_entry=%"PRIxPTR" duplicate_listener=1 distinct_native_call=0",a->token,h->rva,p->rva,a->function-bias);
 a->listeners[listener/64]|=UINT64_C(1)<<(listener%64);
 return true;
}
static bool observer_enter(GumInvocationContext*ctx,struct hook*h,struct invocation*v){
 struct observer_activation*a=calloc(1,sizeof *a);struct run_state*s=v->state;struct detailed_state*d=s->detail;
 if(!a){observer_anomaly(s,s->id,"activation_allocation_failed");return false;}
 a->parent=observer_top;a->hook=h;a->generation=s->id;a->token=++observer_token;
 unsigned listener=(unsigned)(h-P.hooks);a->listeners[listener/64]|=UINT64_C(1)<<(listener%64);
 a->gum_depth=gum_invocation_context_get_depth(ctx);
 a->function=(uintptr_t)ctx->function;a->entry_stack=ctx->cpu_context->rsp;a->return_address=(uintptr_t)gum_invocation_context_get_return_address(ctx);
 a->previous_generation=v->previous?v->previous->id:0;
 a->relative=s->current_relative;a->relative_depth=s->rel_depth;
 a->operation=s->current_operation;a->kind=s->current_kind;
 a->relative_frame=d->relative_frame;a->relative_flags=d->relative_flags;a->relative_cube=d->relative_cube;
 a->push_depth=d->push_depth;a->add_depth=d->add_depth;a->generalization=d->current_generalize;a->heap=d->heap;
 a->validation_active=s->validation_active;a->validation_props=s->validation_props;
 v->activation_token=a->token;v->run_generation=a->generation;a->call=*v;observer_top=a;
 s->activation_begins++;s->activation_live++;
 emit(s,"invocation_begin",false,"activation=%"PRIu64" hook=%s operation=%"PRIu64" gum_depth=%u run_generation=%"PRIu64" parent_activation=%"PRIu64" binding=%s native_lifetime_certified=0",a->token,kind_names[h->kind],v->operation,a->gum_depth,a->generation,a->parent?a->parent->token:0,v->pending_front_binding?"verified_native_pending_set_callsite":"registered_hook_context");
 return true;
}
static void observer_update(struct invocation*v){
 if(observer_top&&observer_top->token==v->activation_token)observer_top->call=*v;
}
static bool observer_matches(struct hook*h,struct invocation*v){
 if(!v->activation_token)return false;
 struct observer_activation*a=observer_top;
 if(!a||a->token!=v->activation_token||a->hook!=h||a->generation!=v->run_generation||!v->state->live||v->state->id!=v->run_generation){
  observer_anomaly(v->state,v->run_generation,"leave_activation_mismatch");return false;
 }
 return true;
}
static void observer_return(struct hook*h,struct invocation*v){
 struct observer_activation*a=observer_top;struct run_state*s=v->state;
 observer_sat_abort(s,a->token,"ancestor_return_without_solver_result");
 emit(s,"invocation_return",false,"activation=%"PRIu64" hook=%s operation=%"PRIu64" gum_depth=%u native_return_observed=1",a->token,kind_names[h->kind],v->operation,a->gum_depth);
 s->activation_returns++;s->activation_live--;
 observer_restore(a,false);observer_top=a->parent;free(a);
}
