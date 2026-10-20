/* Source-derived proof interpretation. Does not assert, assume or change a
 * native expression. A named frame solver is an opaque context, not I or Reach.
 * Semantic schema is separate from the versioned native ABI.
 */
static void semantic_contract(struct run_state*s){
 if(s->contract_emitted)return;
 s->contract_emitted=true;
 emit(s,"run_contract",false,
  "producer=1.6.13-dev semantic_schema=2 frame_encoding=%s activation_tracking=1 abort_terminal_tracking=1 completion_tail_tracking=1 validation_abort_tracking=1 model_epoch_tracking=1 native_exception_transparency_qualified=0 native_unwind_return_restore=%u source_contract=logs2_ic3_relative_20260730 source_sha256=af48a8be676b97c7429f68a15916311941c6521944e3e96f973c897df470eeac worker_sha256=%s details_abi=%u snapshot_policy=%s cubes_enabled=%u context_formula_closed=0 transition_graph_exported=0 rtl_mapping_complete=0 native_query_results_are_not_proof_certificates=1 additional_Dollar_record_schema=1 relative_true=%d relative_false=%d relative_unknown=%d solver_model=%d solver_unsat=%d solver_unsat_assume=%d chain_algorithm=sha256_previous_bytes_plus_record manifest_scope=worker_process",
  frame_chunks_enabled?(frame_inline_enabled?"tuple_chunks_v2":"tuple_chunks_v1"):"members_v1",(gum_interceptor_get_native_unwind_status()==GUM_NATIVE_UNWIND_REQUIRED),P.hash,P.details,full_snapshots?"full":"checkpoints_and_native_events",include_cubes,P.rel_true,P.rel_false,P.rel_unknown,P.sat_true,P.sat_false,P.sat_assume);
 emit(s,"semantic_rule",false,"rule=relative_predecessor formula=F_i_AND_T_AND_S_prime unsat_conclusion=F_i_AND_T_IMPLIES_NOT_S_prime sat_conclusion=predecessor_in_solver_context global_invariant=not_established concrete_reachability=not_established");
 emit(s,"semantic_rule",false,"rule=relative_induction formula=F_i_AND_NOT_S_AND_T_AND_S_prime unsat_conclusion=F_i_AND_NOT_S_AND_T_IMPLIES_NOT_S_prime missing_checks=initial_exclusion_and_global_step_and_context_dependencies");
 emit(s,"semantic_rule",false,"rule=clause_scope blocking_clause=NOT_cube frame_membership=relative_not_global state_vs_transition=must_be_resolved minimize_output=distinct_cube base_repair=not_independently_observed verdict=never_infer_from_fixpoint_clause_count");
}
static bool tracked_scope(enum hook_kind k){
 return k==H_INIT||k==H_FRAME||k==H_PUSH||k==H_BLOCK||k==H_OBLIGATION||k==H_GENERALIZE||k==H_RUN||k==H_STATS;
}
static void semantic_scope_enter(struct run_state*s,struct hook*h,struct invocation*v){
 v->parent_operation=s->current_operation;v->parent_kind=s->current_kind;v->entry_revision=s->context_revision;
 if(!tracked_scope(h->kind))return;
 /* Optimized nested wrappers remain visible as separate observed operations. */
 v->semantic_scope=true;s->current_operation=v->operation;s->current_kind=h->kind;
 emit(s,"operation_enter",false,"operation=%"PRIu64" parent_operation=%"PRIu64" kind=%s native_entry=%"PRIxPTR" entry_revision=%"PRIu64"",v->operation,v->parent_operation,kind_names[h->kind],h->rva,v->entry_revision);
}
static void semantic_scope_leave(struct run_state*s,struct hook*h,struct invocation*v){
 if(h->kind==H_FRAME||h->kind==H_INIT||h->kind==H_ADDCUBE||h->kind==H_SUBSUMPTION||h->kind==H_FRONTREMOVE){
  s->context_revision++;
  emit(s,"context_mutation",false,"operation=%"PRIu64" kind=%s revision=%"PRIu64" coverage=observed_native_mutators_not_complete_solver_formula",v->operation,kind_names[h->kind],s->context_revision);
 }
 if(!v->semantic_scope)return;
 emit(s,"operation_exit",false,"operation=%"PRIu64" parent_operation=%"PRIu64" kind=%s entry_revision=%"PRIu64" exit_revision=%"PRIu64"",v->operation,v->parent_operation,kind_names[h->kind],v->entry_revision,s->context_revision);
 s->current_operation=v->parent_operation;s->current_kind=v->parent_kind;v->semantic_scope=false;
}
static void semantic_query_begin(struct run_state*s,struct hook*h,struct invocation*v){
 v->input_cube_id=include_cubes?full_cube(s,v->cube):0;
 unsigned f=(unsigned)v->flags;
 emit(s,"query_context",false,
 "query=%"PRIu64" operation=%"PRIu64" parent_operation=%"PRIu64" parent_kind=%s native_entry=%"PRIxPTR" frame=%d input_cube_id=%"PRIu64" flags=%u query_class=%s assumes_not_cube_current=%u request_model=%u request_minimize=%u fixed_budget_requested=%u growing_budget_requested=%u entry_revision=%"PRIu64" basis=opaque_frame_solver_context base_check=not_observed abstraction_status=unresolved context_complete=0",
 v->id,v->operation,v->parent_operation,v->parent_kind>=0?kind_names[v->parent_kind]:"none",h->rva,v->frame,v->input_cube_id,f,f&2?"relative_induction":"predecessor_exclusion",(f&2)!=0,(f&1)!=0,(f&4)!=0,(f&8)!=0,(f&16)!=0,v->entry_revision);
 if((f&~31U)||((f&8)&&(f&16)))detail_error(s,"relative_flags_outside_source_contract");
}
static void semantic_query_end(struct run_state*s,struct invocation*v,int result){
 uint64_t output=include_cubes?full_cube(s,v->cube):0;
 const char*conclusion=result==P.rel_false?((v->flags&2)?"relative_inductive_step":"relative_predecessor_exclusion"):result==P.rel_true?"sat_in_frame_context":result==P.rel_unknown?"no_conclusion_resource_limit":"unknown_result_no_conclusion";
 emit(s,"query_conclusion",false,
 "query=%"PRIu64" input_cube_id=%"PRIu64" output_cube_id=%"PRIu64" result_raw=%d conclusion=%s scope=frame_relative entry_revision=%"PRIu64" exit_revision=%"PRIu64" initialization_validated=0 global_step_validated=0 concrete_cex_validated=0 model_witness_exported=0 unsat_core_exported=0 output_initial_repair=not_directly_observed promote_to_global_lemma=0",
 v->id,v->input_cube_id,output,result,conclusion,v->entry_revision,s->context_revision);
}
static void semantic_terminal(struct run_state*s,bool aborted){
 bool good=!s->validation_missing&&gum_interceptor_get_native_unwind_fault()==0&&s->lost==0&&s->read_failures==0&&s->callback_failures==0&&s->relative_other==0&&s->rel_depth==0&&s->activation_live==0&&s->observer_errors==0&&((gum_interceptor_get_native_unwind_status()==GUM_NATIVE_UNWIND_REQUIRED)||s->native_unwind_aborts==0)&&(!s->detail||s->detail->sat_depth==0);
 emit(s,aborted?"run_abort_seal":"run_seal",true,"events_before_seal=%"PRIu64" final_event=%"PRIu64" capture_status=%s relative_queries=%"PRIu64" solver_queries=%"PRIu64" emission_wall_ns_lower_bound=%"PRIu64" context_revision=%"PRIu64" run_closed=1 global_lemma_validation=not_performed session_scope=observed_worker_process activation_begins=%"PRIu64" activation_returns=%"PRIu64" activation_aborts=%"PRIu64" activation_live=%"PRIu64" observer_errors=%"PRIu64" native_unwind_aborts=%"PRIu64" native_exception_transparency_qualified=0 native_unwind_return_restore=%u native_unwind_runtime_fault=%u abort_event=%"PRIu64" native_final_observed=%u terminal_kind=%s",
 s->records,s->final_event,good?"complete":"incomplete",s->relative_calls,s->solver_calls,s->emit_wall_ns,s->context_revision,s->activation_begins,s->activation_returns,s->activation_aborts,s->activation_live,s->observer_errors,s->native_unwind_aborts,(gum_interceptor_get_native_unwind_status()==GUM_NATIVE_UNWIND_REQUIRED),gum_interceptor_get_native_unwind_fault(),s->run_abort_event,!aborted,aborted?"native_aborted_attempt":"native_final");
 s->sealed=true;
 if(s->ledger){pthread_mutex_lock(&ledger_mutex);s->ledger->events=s->records;s->ledger->sealed=good;memcpy(s->ledger->tip,s->chain,65);pthread_mutex_unlock(&ledger_mutex);}
 write_worker_manifest(false);
}
static void semantic_seal(struct run_state*s){semantic_terminal(s,false);}
static void semantic_abort_seal(struct run_state*s){semantic_terminal(s,true);}
