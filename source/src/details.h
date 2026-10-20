/* Complete payloads and native-state observations for a validated ICSeq ABI.
 * Included by events.c after the low-level memory reader/emitter.
 * Every read is observational. No engine helper is called to compute a number.
 * The independent counts below are cross-checked against original getStats /
 * getTotalCubes returns by attached listeners.
 */
#define DETAIL_MAX_ITEMS 10000000
#define DETAIL_CHUNK 32
#define FRAME_CHUNK_MEMBERS 64
#define FRAME_CHUNK_CACHE 16384
static gboolean text_equal(gconstpointer a,gconstpointer b){return strcmp(a,b)==0;}
struct cube_definition { uint64_t id; char hash[65]; int count; bool complete; };
/* Only live membership is retained. A generation mark replaces the second
 * full string-key table; unconfirmed additions roll back after a failed read. */
struct frame_membership { uint64_t cube,seen; int frame; bool confirmed; };
static guint membership_hash(gconstpointer key){
 const struct frame_membership*m=key;return (guint)(m->cube^(m->cube>>32))^(guint)m->frame*2654435761U;
}
static gboolean membership_equal(gconstpointer a,gconstpointer b){
 const struct frame_membership*x=a,*y=b;return x->cube==y->cube&&x->frame==y->frame;
}
struct po_definition { uint64_t id; uintptr_t address; bool defined; uint32_t flags; int cex_size; uintptr_t cube,parent; };
struct sat_inflight {
 uintptr_t site,stack;uint64_t id,query,start,cpu,process,owner;int frame,cube_lits;
};
struct detailed_state {
 GHashTable *cubes,*names,*pos,*members,*nodes,*frame_chunks;
 GHashTable *parity_counts[4];uint64_t lens_samples;
 struct sat_inflight sat_stack[32];unsigned sat_depth;
 uint64_t cube_ids,po_ids,operation,snapshot,queue_snapshot,gen_id,current_generalize,frame_chunk_ids;
 uint64_t total_checks,total_mismatch,stats_checks,stats_mismatch,frame_scans,queue_scans,observed_enqueues,observed_dequeues;
 uintptr_t heap,circuit,relative_cube; bool model_emitted; unsigned push_depth,add_depth;
 int model_vars,model_latches;
 int result_raw,fixpoint,cubes_total,cubes_fix,flops,coi; bool have_final;
 int relative_frame,relative_flags;
};
static uint64_t clock_ns(clockid_t clock){struct timespec t;if(clock_gettime(clock,&t))return 0;return (uint64_t)t.tv_sec*1000000000ULL+t.tv_nsec;}
static bool full_abi(void){return P.details==1;}
static bool atlas_names(void){return !strcmp(P.hash,"690e3ca961c62999509196ddb8a7f94a1707c6b129fa6f392f25b038206dad47");}
static bool name_abi(void){return full_abi()||atlas_names();}
static void detail_error(struct run_state*s,const char *where){
 if(s){s->read_failures++;emit(s,"capture_error",false,"operation=%s complete=0",where);}
 __atomic_add_fetch(&read_failures,1,__ATOMIC_RELAXED);
}
static struct detailed_state *ds(struct run_state*s){
 if(!s->detail){
  s->detail=calloc(1,sizeof *s->detail);
  if(!s->detail){s->lost++;return NULL;}
  struct detailed_state*d=s->detail;
  d->cubes=g_hash_table_new_full(g_str_hash,text_equal,free,free);
  d->names=g_hash_table_new(g_direct_hash,g_direct_equal);
  d->pos=g_hash_table_new_full(g_direct_hash,g_direct_equal,NULL,free);
  d->members=g_hash_table_new_full(membership_hash,membership_equal,free,NULL);
  d->nodes=g_hash_table_new(g_direct_hash,g_direct_equal);
  d->frame_chunks=g_hash_table_new_full(g_str_hash,text_equal,free,free);
  d->fixpoint=d->cubes_total=d->cubes_fix=d->flops=d->coi=-1;
  d->relative_frame=d->relative_flags=-1;
 }
 return s->detail;
}
static void destroy_details(struct run_state*s){
 struct detailed_state*d=s->detail;if(!d)return;
 g_hash_table_destroy(d->cubes);g_hash_table_destroy(d->names);g_hash_table_destroy(d->pos);
 g_hash_table_destroy(d->members);g_hash_table_destroy(d->frame_chunks);g_hash_table_destroy(d->nodes);for(int i=0;i<4;i++)if(d->parity_counts[i])g_hash_table_destroy(d->parity_counts[i]);free(d);s->detail=NULL;
}
static void model_epoch_begin(struct run_state*s){
 struct detailed_state*d=s->detail;s->model_epoch++;
 g_hash_table_remove_all(d->cubes);g_hash_table_remove_all(d->names);
 g_hash_table_remove_all(d->pos);g_hash_table_remove_all(d->members);g_hash_table_remove_all(d->nodes);
 g_hash_table_remove_all(d->frame_chunks);
 d->model_emitted=false;d->circuit=0;
 emit(s,"model_epoch_begin",false,"mapping_equivalence=not_assumed membership_baseline=reset old_records_retained=1 boundary=native_init_entry");
}
static bool vec_view(struct run_state*s,uintptr_t v,uintptr_t*data,int*count){
 int n=read_i32(s,v,(int)P.cube_size);uintptr_t p=0;
 if(n<0||n>DETAIL_MAX_ITEMS||!read_u64(v+P.cube_data,&p)||(n&&!p)){detail_error(s,"vector_layout");return false;}
 *data=p;*count=n;return true;
}
static void sha_begin(js_sha*c){static const uint32_t a[8]={0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};memset(c,0,sizeof *c);memcpy(c->s,a,sizeof a);}
static void sha_end(js_sha*c,char hex[65]){
 uint64_t bits=c->bytes*8;c->b[c->n++]=0x80;if(c->n>56){memset(c->b+c->n,0,64-c->n);js_block(c,c->b);c->n=0;}
 memset(c->b+c->n,0,56-c->n);for(int i=0;i<8;i++)c->b[63-i]=(unsigned char)(bits>>(8*i));js_block(c,c->b);
 static const char h[]="0123456789abcdef";for(int i=0;i<32;i++){unsigned b=(c->s[i/4]>>(24-8*(i%4)))&255;hex[2*i]=h[b>>4];hex[2*i+1]=h[b&15];}hex[64]=0;
}
static void hexbytes(const unsigned char*in,size_t n,char*out){static const char h[]="0123456789abcdef";for(size_t i=0;i<n;i++){out[i*2]=h[in[i]>>4];out[i*2+1]=h[in[i]&15];}out[n*2]=0;}
/* Diagnostic reads do not increment capture read failures or mutate binding.
 * A readable address alone does not establish native object lifetime. */
static void model_context_observe(struct run_state*s,const char*cause,uintptr_t actual_jip){
 if(!full_abi())return;
 struct detailed_state*d=s->detail;if(!d)return;
 uintptr_t bound=0,actual=0;int32_t bn=-1,bl=-1,an=-1,al=-1;
 bool br=read_u64(s->jip+64,&bound),ar=actual_jip&&read_u64(actual_jip+64,&actual);
 bool bd=br&&bound&&read_bytes(bound+24,&bn,4)&&read_bytes(bound+16,&bl,4);
 bool ad=ar&&actual&&read_bytes(actual+24,&an,4)&&read_bytes(actual+16,&al,4);
 emit(s,"model_context",false,"cause=%s bound_jip=%"PRIxPTR" seq=%"PRIxPTR" epoch_circuit=%"PRIxPTR" epoch_vars=%d epoch_latches=%d bound_read=%u bound_circuit=%"PRIxPTR" bound_dims_read=%u bound_vars=%d bound_latches=%d actual_jip=%"PRIxPTR" actual_read=%u actual_circuit=%"PRIxPTR" actual_dims_read=%u actual_vars=%d actual_latches=%d run_unwound=%u lifetime_verified=0",
 cause,s->jip,s->seq,d->circuit,d->model_vars,d->model_latches,br,bound,bd,bn,bl,actual_jip,ar,actual,ad,an,al,s->run_unwound);
}
static void signal_definition(struct run_state*s,uint32_t variable){
 if(!name_abi())return;
 struct detailed_state*d=ds(s);if(!d||!d->model_emitted)return;
 gpointer key=(gpointer)(uintptr_t)((uint64_t)variable+1);
 if(g_hash_table_contains(d->names,key))return;
 uintptr_t circ=0,names=0;int count=-1;
 if(!read_u64(s->jip+64,&circ)||!circ){detail_error(s,"circuit_pointer");return;}
 int nvars=atlas_names()?read_i32(s,circ,8):read_i32(s,circ,24),latches=atlas_names()?0:read_i32(s,circ,16);
 if(nvars<0||nvars>DETAIL_MAX_ITEMS||latches<0||latches>nvars){detail_error(s,"circuit_dimensions");return;}
 if(full_abi()&&(circ!=d->circuit||nvars!=d->model_vars||latches!=d->model_latches)){
  model_context_observe(s,"signal_context_changed",0);detail_error(s,"signal_model_context_changed");return;
 }
 g_hash_table_add(d->names,key);
 uintptr_t name=0;bool retained=false;
 if(vec_view(s,circ,&names,&count)&&variable<(uint32_t)count)retained=read_u64(names+8*(uintptr_t)variable,&name)&&name;
 uintptr_t nexts=0,inits=0,active=0;uint32_t next=0;int init=0;unsigned char enabled=0;
 bool nextok=false,initok=false,activeok=false;
 if(full_abi()&&variable<(uint32_t)nvars){
  int nn=read_i32(s,circ,40),ni=read_i32(s,circ,56),na=read_i32(s,circ,72);
  if(variable<(uint32_t)nn&&nn>=0&&read_u64(circ+32,&nexts))nextok=read_bytes(nexts+4*(uintptr_t)variable,&next,4);
  if(variable<(uint32_t)ni&&ni>=0&&read_u64(circ+48,&inits))initok=read_bytes(inits+4*(uintptr_t)variable,&init,4);
  if(variable<(uint32_t)na&&na>=0&&read_u64(circ+64,&active))activeok=read_bytes(active+variable,&enabled,1);
 }
 emit(s,"signal",false,"variable=%u role=%s name_status=%s next_known=%u next_raw=%08x init_known=%u init_raw=%d active_known=%u active=%u mapping=retained_engine_model_not_reconstructed_RTL",
  variable,atlas_names()?"unqualified_role":variable<(uint32_t)latches?"state":variable<(uint32_t)nvars?"input":"auxiliary",retained?"retained":"unavailable",nextok,next,initok,init,activeok,enabled);
 if(!retained)return;
 uint64_t offset=0;bool ended=false;char encoded[513];unsigned char buf[256];
 while(offset<16777216){
  /* Read only up to the end of the current memory page. */
  size_t take=sizeof buf,left=4096-((name+offset)&4095);if(take>left)take=left;
  if(!read_bytes(name+offset,buf,take)){detail_error(s,"retained_signal_name");break;}
  size_t n=0;while(n<take&&buf[n])n++;
  hexbytes(buf,n,encoded);emit(s,"signal_name_chunk",false,"variable=%u offset=%"PRIu64" bytes=%zu utf8_hex=%s",variable,offset,n,encoded);
  offset+=n;if(n<take){ended=true;break;}
 }
 emit(s,"signal_name_end",false,"variable=%u bytes=%"PRIu64" complete=%u",variable,offset,ended);
 if(!ended)detail_error(s,"retained_signal_name_incomplete");
}
static void model_record(struct run_state*s){
 if(atlas_names()){
  struct detailed_state*d=ds(s);if(!d||d->model_emitted)return;
  uintptr_t circ=0,names=0;int count=0;
  if(!read_u64(s->jip+64,&circ)||!circ||!vec_view(s,circ,&names,&count)){detail_error(s,"atlas_atom_name_table");return;}
  d->model_emitted=true;d->circuit=circ;g_hash_table_remove_all(d->cubes);
  emit(s,"model",false,"model_instance=%"PRIu64" worker_sha256=%s n_vars=%d n_latches=-1 n_inputs=-1 formula_index_shift=3 formula_sign_mask=4 formula_composite_mask=2 signal_names=on_first_reference mapping=direct_retained_atom_names role_mapping=unqualified native_context_known=0 frames_available=0 queues_available=0",
       s->id,P.hash,count);
  return;
 }
 if(!full_abi())return;
 struct detailed_state*d=ds(s);if(!d||d->model_emitted)return;
 uintptr_t circ=0,cfg=0;if(!read_u64(s->jip+64,&circ)||!circ||!read_u64(s->seq,&cfg)){detail_error(s,"model_header");return;}
 int n=read_i32(s,circ,24),l=read_i32(s,circ,16),inputs=read_i32(s,circ,20);
 if(n<0||n>DETAIL_MAX_ITEMS||l<0||l>n||inputs<0){detail_error(s,"model_dimensions");return;}
 d->model_emitted=true;d->circuit=circ;d->model_vars=n;d->model_latches=l;g_hash_table_remove_all(d->cubes);
 emit(s,"model",false,"model_instance=%"PRIu64" worker_sha256=%s circuit_address=%"PRIxPTR" n_vars=%d n_latches=%d n_inputs=%d engine_index=%d restart_mode=%d properties=%d bad_raw=%08x start_raw=%08x formula_index_shift=3 formula_sign_mask=4 formula_composite_mask=2 signal_names=on_first_reference",
 s->id,P.hash,circ,n,l,inputs,read_i32(s,cfg,0),read_i32(s,cfg,4),read_i32(s,s->seq,224),(unsigned)read_i32(s,s->seq,264),(unsigned)read_i32(s,s->seq,268));
}
static uint64_t capture_vector_data(struct run_state*s,uintptr_t data,int total,const char*domain){
 struct detailed_state*d=ds(s);if(!d)return 0;
 if(total<0||total>DETAIL_MAX_ITEMS||(total&&!data)){detail_error(s,"payload_dimensions");return 0;}
 js_sha hash;sha_begin(&hash);js_update(&hash,(const unsigned char*)domain,strlen(domain)+1);
 uint32_t count=(uint32_t)total;js_update(&hash,(unsigned char*)&count,4);uint32_t raw[256];
 for(int at=0;at<total;){int n=total-at;if(n>256)n=256;
  if(!read_bytes(data+(uintptr_t)at*4,raw,(size_t)n*4)){detail_error(s,"payload_hash_read");return 0;}
  js_update(&hash,(unsigned char*)raw,(size_t)n*4);at+=n;
 }
 char hex[65];sha_end(&hash,hex);
 struct cube_definition*known=g_hash_table_lookup(d->cubes,hex);if(known)return known->id;
 /* A bounded deduplication cache. Re-emission creates a fresh monotonic ID;
  * complete definitions remain on disk, so eviction never drops evidence. */
 if(g_hash_table_size(d->cubes)>=65536)g_hash_table_remove_all(d->cubes);
 known=calloc(1,sizeof *known);if(!known){s->lost++;return 0;}
 known->id=++d->cube_ids;known->count=total;memcpy(known->hash,hex,sizeof hex);
 g_hash_table_insert(d->cubes,strdup(hex),known);
 uint64_t loss=s->lost;bool complete=true;
 emit(s,"cube_definition",false,"cube_id=%"PRIu64" domain=%s literals=%d sha256=%s chunks=%d model_qualified=%u order=native scope=engine_cube_not_a_proven_global_lemma",known->id,domain,total,hex,(total+DETAIL_CHUNK-1)/DETAIL_CHUNK,d->model_emitted);
 for(int at=0;at<total;){int n=total-at;if(n>DETAIL_CHUNK)n=DETAIL_CHUNK;
  if(!read_bytes(data+(uintptr_t)at*4,raw,(size_t)n*4)){detail_error(s,"payload_chunk_read");complete=false;break;}
  char values[DETAIL_CHUNK*9+1],decoded[DETAIL_CHUNK*32+1];size_t p=0,q=0;
  for(int i=0;i<n;i++){
   p+=(size_t)snprintf(values+p,sizeof values-p,"%s%08x",i?",":"",raw[i]);
   if(!strcmp(domain,"jip_formula")&&name_abi()){
    const char*special=raw[i]==0xfffffff8U?"true":raw[i]==0xfffffffcU?"false":raw[i]==0xfffffff0U?"undef":raw[i]==0xfffffff4U?"error":NULL;
    if(special)q+=(size_t)snprintf(decoded+q,sizeof decoded-q,"%s%s",i?",":"",special);
    else q+=(size_t)snprintf(decoded+q,sizeof decoded-q,"%s%s%c%u",i?",":"",raw[i]&4?"!":"",raw[i]&2?'n':'v',raw[i]>>3);
   }
  }
  values[p]=0;decoded[q]=0;
  emit(s,"cube_chunk",false,"cube_id=%"PRIu64" offset=%d count=%d values=%s formulas=%s",known->id,at,n,values,q?decoded:"raw_only");
  if(!strcmp(domain,"jip_formula")&&name_abi())for(int i=0;i<n;i++)if(!(raw[i]&2)&&(raw[i]>>3)<0x1ffffffeU)signal_definition(s,raw[i]>>3);
  at+=n;
 }
 known->complete=complete&&s->lost==loss;
 emit(s,"cube_definition_end",false,"cube_id=%"PRIu64" literals=%d complete=%u",known->id,total,known->complete);
 return known->id;
}
static uint64_t full_cube(struct run_state*s,uintptr_t cube){
 uintptr_t data=0;int n=0;if(!cube||!vec_view(s,cube,&data,&n))return 0;
 return capture_vector_data(s,data,n,"jip_formula");
}
static void sample_cube(struct run_state*s,uintptr_t cube,uint64_t query,const char*when){
 if(!include_cubes||!cube)return;
 uint64_t id=full_cube(s,cube);struct detailed_state*d=ds(s);
 emit(s,"cube",false,"query=%"PRIu64" generalization=%"PRIu64" when=%s cube_id=%"PRIu64" total=%d shown=%d truncated=0 capture_complete=%u encoding=chunked_raw_jip_formula_u32",query,d?d->current_generalize:0,when,id,cube_size(s,cube),cube_size(s,cube),id!=0);
}
static bool frontier_range(struct run_state*s,int frame,uintptr_t*begin,size_t*count){
 int n=read_i32(s,s->seq,112);uintptr_t first=0,fr=0,a=0,b=0,cap=0;
 if(n<0||n>DETAIL_MAX_ITEMS||!read_u64(s->seq+104,&first)){detail_error(s,"frontier_vector");return false;}
 fr=frame<0?s->seq+120:first+(uintptr_t)frame*32;
 if(frame>=n||!read_u64(fr,&a)||!read_u64(fr+8,&b)||!read_u64(fr+16,&cap)||b<a||cap<b||(b-a)%8||(b-a)/8>DETAIL_MAX_ITEMS){detail_error(s,"frontier_bounds");return false;}
 *begin=a;*count=(b-a)/8;return true;
}
static bool population(struct run_state*s,int64_t*clauses,int64_t*invars){
 if(!full_abi())return false;
 int n=read_i32(s,s->seq,112);if(n<0||n>DETAIL_MAX_ITEMS)return false;
 int64_t sum=0;uintptr_t p;size_t count;
 for(int i=1;i<n;i++){if(!frontier_range(s,i,&p,&count))return false;sum+=(int64_t)count;}
 if(!frontier_range(s,-1,&p,&count))return false;
 *clauses=sum;*invars=(int64_t)count;return true;
}
static void native_fields_ex(struct run_state*s,char out[768],bool final){
 int64_t clauses=-1,invars=-1;bool okay=population(s,&clauses,&invars);
 int calls=read_i32(s,s->seq,P.calls_offset),sat=full_abi()?read_i32(s,s->seq,292):-1;
 snprintf(out,768,"native_available=%u %s=%"PRId64" invariants=%"PRId64" sat_calls=%d native_sat=%d sat_percent=%.6f obligations=%d pre_bad=%d pre_other=%d generalize=%d native_added=%d native_removed=%d",
 okay,final?"frontier_clauses":"clauses",clauses,invars,calls,sat,calls>0&&sat>=0?100.0*sat/calls:calls==0?0.0:-1.0,obligations(s),read_i32(s,s->seq,P.pre_bad_offset),read_i32(s,s->seq,P.pre_other_offset),read_i32(s,s->seq,P.generalize_offset),full_abi()?read_i32(s,s->seq,300):-1,full_abi()?read_i32(s,s->seq,304):-1);
 size_t used=strlen(out);
 if(s->parity_enabled){
  int n=snprintf(out+used,768-used," generalize_success=%"PRIu64" generalized_lits=%"PRIu64,s->successful_generalizations,s->removed_generalization_literals);
  if(n<0||(size_t)n>=768-used){detail_error(s,"scalar_field_size");return;}
  used+=(size_t)n;
  if(!final)snprintf(out+used,768-used," relative_sat=%"PRIu64" relative_unsat=%"PRIu64" relative_limit=%"PRIu64,s->relative_sat,s->relative_unsat,s->relative_limit);
 }
}
static void native_fields(struct run_state*s,char out[768]){native_fields_ex(s,out,false);}
/* Versioned canonical encoding: ordered (cube_id:u64, native packed:u32),
 * little-endian. No pointer identity, sampling, or recursive delta history. */
static void frame_le(unsigned char*out,uint64_t value,unsigned bytes){
 for(unsigned i=0;i<bytes;i++)out[i]=(unsigned char)(value>>(8*i));
}
static void frame_hash_begin(js_sha*h,uint64_t epoch,int frame,size_t count){
 static const char domain[]="jipstats-frame-tuples-v1";unsigned char header[20];
 sha_begin(h);js_update(h,(const unsigned char*)domain,sizeof domain);
 frame_le(header,epoch,8);frame_le(header+8,(uint32_t)frame,4);frame_le(header+12,count,8);
 js_update(h,header,sizeof header);
}
static uint64_t frame_chunk(struct run_state*s,const unsigned char*data,unsigned count){
 struct detailed_state*d=ds(s);js_sha h;char digest[65];unsigned char size[4];
 static const char domain[]="jipstats-frame-chunk-v1";
 sha_begin(&h);js_update(&h,(const unsigned char*)domain,sizeof domain);
 frame_le(size,count,4);js_update(&h,size,4);js_update(&h,data,(size_t)count*12);sha_end(&h,digest);
 uint64_t*known=g_hash_table_lookup(d->frame_chunks,digest);if(known)return *known;
 if(g_hash_table_size(d->frame_chunks)>=FRAME_CHUNK_CACHE)g_hash_table_remove_all(d->frame_chunks);
 uint64_t id=++d->frame_chunk_ids,loss=s->lost;char hex[FRAME_CHUNK_MEMBERS*24+1];
 hexbytes(data,(size_t)count*12,hex);
 emit(s,"frame_chunk",false,"chunk_id=%"PRIu64" members=%u sha256=%s tuples_hex=%s encoding=cube_u64_packed_u32_le complete=1",id,count,digest,hex);
 if(s->lost!=loss)return 0;
 known=malloc(sizeof *known);char*key=strdup(digest);
 if(!known||!key){free(known);free(key);s->lost++;return 0;}
 *known=id;g_hash_table_insert(d->frame_chunks,key,known);return id;
}
static void frame_snapshot(struct run_state*s,const char*cause,uint64_t operation){
 if(!full_abi())return;
 if(!full_snapshots&&strcmp(cause,"initial")&&strcmp(cause,"frame_created")&&strcmp(cause,"push_end")&&strcmp(cause,"final"))return;
 struct detailed_state*d=ds(s);if(!d)return;
 int n=read_i32(s,s->seq,112);if(n<0||n>DETAIL_MAX_ITEMS){detail_error(s,"frame_snapshot_dimensions");return;}
 uint64_t snap=++d->snapshot;d->frame_scans++;
 bool complete=true;size_t total=0;
 uint64_t initial_loss=s->lost,initial_read_failures=s->read_failures;
 emit(s,"frames_begin",false,"snapshot=%"PRIu64" cause=%s operation=%"PRIu64" frontier_count=%d invariant_frame=-1",snap,cause,operation,n);
 for(int f=0;f<=n;f++){
  int frame=f==n?-1:f;uintptr_t data=0;size_t count=0;
  if(!frontier_range(s,frame,&data,&count)){complete=false;break;}
  bool inline_frame=frame_inline_enabled&&count<=FRAME_CHUNK_MEMBERS;uint64_t one_chunk=0;
  if(!inline_frame)emit(s,"frame",false,"snapshot=%"PRIu64" frame=%d cubes=%zu scope=%s",snap,frame,count,frame<0?"engine_invariants":"relative_frontier");
  js_sha content;unsigned char tuples[FRAME_CHUNK_MEMBERS*12];unsigned buffered=0;size_t refs=0;
  if(frame_chunks_enabled)frame_hash_begin(&content,s->model_epoch,frame,count);
  for(size_t k=0;k<count;k++){
   uintptr_t cube=0;if(!read_u64(data+8*k,&cube)){detail_error(s,"frame_cube_pointer");complete=false;break;}
   uint64_t id=full_cube(s,cube);uint32_t packed=0;
   if(!id||!read_bytes(cube+16,&packed,4)){detail_error(s,"frame_member_payload");complete=false;break;}
   int maxlevel=((int32_t)(packed<<1))>>1;
   if(frame_chunks_enabled){
    frame_le(tuples+buffered*12,id,8);frame_le(tuples+buffered*12+8,packed,4);buffered++;
    if(buffered==FRAME_CHUNK_MEMBERS||k+1==count){
     js_update(&content,tuples,(size_t)buffered*12);uint64_t chunk=frame_chunk(s,tuples,buffered);
     if(!chunk){complete=false;break;}
     if(inline_frame)one_chunk=chunk;
     else emit(s,"frame_chunk_ref",false,"snapshot=%"PRIu64" frame=%d offset=%zu chunk_id=%"PRIu64" members=%u",snap,frame,k+1-buffered,chunk,buffered);
     buffered=0;refs++;
    }
   }else emit(s,"frame_member",false,"snapshot=%"PRIu64" frame=%d index=%zu cube_id=%"PRIu64" max_level=%d validated=%u",snap,frame,k,id,maxlevel,packed>>31);
   struct frame_membership key={.cube=id,.frame=frame};
   struct frame_membership*member=g_hash_table_lookup(d->members,&key);
   if(!member){
    member=calloc(1,sizeof *member);
    if(!member){s->lost++;complete=false;break;}
    member->cube=id;member->frame=frame;g_hash_table_add(d->members,member);
   }
   /* Set membership changes once per cube/frame, while tuple chunks above
      retain every ordered occurrence and packed flag. Failed scans still
      discard unconfirmed entries below, allowing a later scan to retry. */
   bool already_seen=member->seen==snap;
   member->seen=snap;
   if(!member->confirmed&&!already_seen)emit(s,"frame_membership_add",false,"snapshot=%"PRIu64" frame=%d cube_id=%"PRIu64" cause=%s operation=%"PRIu64,snap,frame,id,cause,operation);
   total++;
  }
  complete=complete&&s->lost==initial_loss&&s->read_failures==initial_read_failures;
  if(frame_chunks_enabled){
   char digest[65];sha_end(&content,digest);
   if(inline_frame)emit(s,"frame",false,"snapshot=%"PRIu64" frame=%d cubes=%zu scope=%s ref_chunk=%"PRIu64" sha256=%s complete=%u",snap,frame,count,frame<0?"engine_invariants":"relative_frontier",one_chunk,digest,complete);
   else emit(s,"frame_manifest_end",false,"snapshot=%"PRIu64" frame=%d cubes=%zu refs=%zu sha256=%s complete=%u",snap,frame,count,refs,digest,complete);
  }
  if(!complete)break;
 }
 GHashTableIter it;gpointer key;g_hash_table_iter_init(&it,d->members);
 while(g_hash_table_iter_next(&it,&key,NULL)){
  struct frame_membership*member=key;
  if(complete&&member->seen==snap)member->confirmed=true;
  else if(complete){
   if(member->confirmed)emit(s,"frame_membership_remove",false,"snapshot=%"PRIu64" frame=%d cube_id=%"PRIu64" cause=%s operation=%"PRIu64,snap,member->frame,member->cube,cause,operation);
   g_hash_table_iter_remove(&it);
  }else if(!member->confirmed)g_hash_table_iter_remove(&it);
 }
 emit(s,"frames_end",false,"snapshot=%"PRIu64" members=%zu complete=%u",snap,total,complete&&s->lost==initial_loss&&s->read_failures==initial_read_failures);
}
static struct po_definition*reserve_po(struct run_state*s,uintptr_t address){
 if(!address)return NULL;
 struct detailed_state*d=ds(s);if(!d)return NULL;
 struct po_definition*p=g_hash_table_lookup(d->pos,(gpointer)address);
 if(!p){p=calloc(1,sizeof *p);if(!p){s->lost++;return NULL;}p->id=++d->po_ids;p->address=address;g_hash_table_insert(d->pos,(gpointer)address,p);}
 return p;
}
static uint64_t define_po(struct run_state*s,uintptr_t address){
 struct po_definition*first=reserve_po(s,address);if(!first)return 0;uint64_t first_id=first->id;
 uintptr_t p=address;unsigned count=0;
 while(p){
  struct po_definition*po=reserve_po(s,p);if(!po)break;
  uint32_t flags;int path;uintptr_t cube=0,parent=0;
  if(!read_bytes(p,&flags,4)||!read_bytes(p+4,&path,4)||!read_u64(p+8,&cube)||!read_u64(p+16,&parent)){detail_error(s,"proof_obligation");break;}
  bool existed=po->defined;
  if(existed&&po->flags==flags&&po->cex_size==path&&po->cube==cube&&po->parent==parent)break;
  int before_frame=existed?((int32_t)po->flags)>>2:-1;
  po->defined=true;po->flags=flags;po->cex_size=path;po->cube=cube;po->parent=parent;
  struct po_definition*pa=reserve_po(s,parent);
  uint64_t id=full_cube(s,cube);
  emit(s,existed?"obligation_update":"obligation",false,"obligation_id=%"PRIu64" parent_id=%"PRIu64" cube_id=%"PRIu64" frame=%d cex_size=%d may=%u disabled=%u relation=predecessor_to_parent native_address=%"PRIxPTR" previous_frame=%d",
       po->id,pa?pa->id:0,id,((int32_t)flags)>>2,path,flags&1,(flags>>1)&1,p,before_frame);
  p=parent;if(++count>DETAIL_MAX_ITEMS){detail_error(s,"obligation_chain_bounds");break;}
 }
 return first_id;
}
static uintptr_t queue_top(struct run_state*s,uintptr_t heap){
 uintptr_t tree=0,node=0,po=0;
 if(!read_u64(heap+40,&tree)||tree==heap+24)return 0;
 if(!read_u64(tree+40,&node)||!read_u64(node+16,&po)){detail_error(s,"queue_top");return 0;}
 return po;
}
static void queue_snapshot(struct run_state*s,const char*cause,uint64_t operation){
 if(!full_abi())return;
 if(!full_snapshots&&strcmp(cause,"sample")&&strcmp(cause,"trace_attempt")&&strcmp(cause,"block_leave"))return;
 struct detailed_state*d=ds(s);if(!d||!d->heap)return;
 uintptr_t mgr=d->heap;uint64_t snapshot=++d->queue_snapshot;d->queue_scans++;bool complete=true;
 emit(s,"queues_begin",false,"snapshot=%"PRIu64" cause=%s operation=%"PRIu64" short_queue=%d long_queue=%d sampling_window=%d max_sampling_window=%d short_window=%d long_window=%d short_processed=%d long_processed=%d early_push_countdown=%d budget=%d",
 snapshot,cause,operation,read_i32(s,mgr,52),read_i32(s,mgr,116),read_i32(s,mgr,12),read_i32(s,mgr,16),read_i32(s,mgr,20),read_i32(s,mgr,24),read_i32(s,mgr,4),read_i32(s,mgr,8),read_i32(s,mgr,36),read_i32(s,mgr,40));
 GHashTable*nodes=g_hash_table_new(g_direct_hash,g_direct_equal);
 for(unsigned q=0;q<2;q++){
  uintptr_t heap=mgr+(q?112:48),tree=0;int expected=read_i32(s,heap,4);
  if(expected<0||expected>DETAIL_MAX_ITEMS||!read_u64(heap+32,&tree)){detail_error(s,"queue_header");complete=false;break;}
  GArray*stack=g_array_new(FALSE,FALSE,sizeof(uintptr_t));GHashTable*visited=g_hash_table_new(g_direct_hash,g_direct_equal);
  if(tree)g_array_append_val(stack,tree);
  size_t observed=0;
  while(stack->len&&observed<=(size_t)expected){
   uintptr_t t=g_array_index(stack,uintptr_t,stack->len-1);g_array_set_size(stack,stack->len-1);
   if(g_hash_table_contains(visited,(gpointer)t)){detail_error(s,"queue_tree_cycle");complete=false;break;}g_hash_table_add(visited,(gpointer)t);
   uintptr_t left=0,right=0,node=0;int level=read_i32(s,t,32);
   if(!read_u64(t+16,&left)||!read_u64(t+24,&right)||!read_u64(t+40,&node)){detail_error(s,"queue_tree_node");complete=false;break;}
   if(right)g_array_append_val(stack,right);
   if(left)g_array_append_val(stack,left);
   uintptr_t head=t+40;
   while(node!=head&&observed<=(size_t)expected){
    uintptr_t po=0,next=0;if(!read_u64(node+16,&po)||!read_u64(node,&next)||!po||next==node){detail_error(s,"queue_list_node");complete=false;break;}
    uint64_t id=define_po(s,po);g_hash_table_insert(nodes,(gpointer)node,(gpointer)(uintptr_t)id);
    emit(s,"queue_member",false,"snapshot=%"PRIu64" queue=%s index=%zu frame=%d obligation_id=%"PRIu64,snapshot,q?"long":"short",observed,level,id);
    node=next;observed++;
   }
   if(!complete)break;
  }
  if(observed!=(size_t)expected){detail_error(s,"queue_count_mismatch");complete=false;}
  emit(s,"queue_end",false,"snapshot=%"PRIu64" queue=%s observed=%zu native_count=%d complete=%u",snapshot,q?"long":"short",observed,expected,complete);
  g_hash_table_destroy(visited);g_array_free(stack,TRUE);
  if(!complete)break;
 }
 if(complete){
  GHashTableIter it;gpointer node,po;g_hash_table_iter_init(&it,d->nodes);
  while(g_hash_table_iter_next(&it,&node,&po))if(!g_hash_table_contains(nodes,node)){
   uint64_t identity=(uint64_t)(uintptr_t)po;
   emit(s,"queue_membership_remove",false,"snapshot=%"PRIu64" obligation_id=%"PRIu64" list_node=%"PRIxPTR" cause=%s operation=%"PRIu64" semantics=observed_membership_delta_not_discharge",snapshot,identity,(uintptr_t)node,cause,operation);
   d->observed_dequeues++;
  }
  g_hash_table_destroy(d->nodes);d->nodes=nodes;
 }else g_hash_table_destroy(nodes);
 emit(s,"queues_end",false,"snapshot=%"PRIu64" complete=%u",snapshot,complete);
}
static void verify_native_final(struct run_state*s){
 struct detailed_state*d=ds(s);if(!d||!full_abi()||!d->have_final)return;
 int n=read_i32(s,s->seq,112);uintptr_t circ=d->circuit,active=0;
 bool okay=n>=0&&n<=DETAIL_MAX_ITEMS&&circ&&read_u64(circ+64,&active);
 int total=0,fixed=0,flops=0,coi=0;
 GHashTable*support=g_hash_table_new(g_direct_hash,g_direct_equal);
 for(int f=1;okay&&f<=n;f++){
  if(f==d->fixpoint)continue;
  uintptr_t data=0;size_t count=0;if(!frontier_range(s,f==n?-1:f,&data,&count)){okay=false;break;}
  total+=(int)count;
  if(f<d->fixpoint)continue;
  fixed+=(int)count;
  for(size_t k=0;okay&&k<count;k++){
   uintptr_t cube=0,literals=0;int nr=0;
   if(!read_u64(data+8*k,&cube)||!vec_view(s,cube,&literals,&nr)){okay=false;break;}
   uint32_t buffer[256];
   for(int off=0;okay&&off<nr;){
    int take=nr-off;if(take>256)take=256;
    if(!read_bytes(literals+(uintptr_t)off*4,buffer,take*4)){okay=false;break;}
    for(int j=0;j<take;j++)if(!(buffer[j]&2))g_hash_table_add(support,(gpointer)(uintptr_t)((buffer[j]>>3)+1ULL));
    off+=take;
   }
  }
 }
 int latches=circ?read_i32(s,circ,16):-1;
 if(latches<0||latches>DETAIL_MAX_ITEMS)okay=false;
 for(int i=0;okay&&i<latches;i++){
  unsigned char enabled=0;if(!read_bytes(active+i,&enabled,1)){okay=false;break;}
  if(enabled){coi++;if(g_hash_table_contains(support,(gpointer)(uintptr_t)(i+1ULL)))flops++;}
 }
 g_hash_table_destroy(support);
 bool match=okay&&total==d->cubes_total&&fixed==d->cubes_fix&&flops==d->flops&&coi==d->coi;
 if(!match)d->stats_mismatch++;
 emit(s,"native_final_check",false,"read_complete=%u match=%u observed_clauses=%d observed_fixpoint_clauses=%d observed_invariant_flops=%d observed_coi_flops=%d original_clauses=%d original_fixpoint_clauses=%d original_invariant_flops=%d original_coi_flops=%d",okay,match,total,fixed,flops,coi,d->cubes_total,d->cubes_fix,d->flops,d->coi);
 if(!okay)detail_error(s,"native_final_independent_check");
}
static void full_final(struct run_state*s,int result){
 struct detailed_state*d=ds(s);char native[768];native_fields_ex(s,native,true);
 /* At the final boundary clauses includes the invariant frame, matching getStats. */
 const char*name=result==P.valid?"valid":result==P.cex?"cex":"undetermined";
 int count=full_abi()?read_i32(s,s->seq,112):-1;
 if(full_abi())frame_snapshot(s,"final",0);
 emit(s,"final",true,"result=%s result_raw=%d depth=%d %s final_native_stats_available=%u clauses=%d fixpoint_frame=%d fixpoint_clauses=%d invariant_flops=%d coi_flops=%d frontier_count=%d relative_calls=%"PRIu64" relative_sat=%"PRIu64" relative_unsat=%"PRIu64" relative_limit=%"PRIu64" solver_calls=%"PRIu64" solver_sat=%"PRIu64" solver_unsat=%"PRIu64" solver_limit=%"PRIu64" generalize_calls=%"PRIu64" push_calls=%"PRIu64" block_calls=%"PRIu64" obligation_process_calls=%"PRIu64" obligations_created=%d population_checks=%"PRIu64" population_mismatch=%"PRIu64" final_stats_checks=%"PRIu64" final_stats_mismatch=%"PRIu64" cube_definitions=%"PRIu64" obligation_identities=%"PRIu64" frame_snapshots=%"PRIu64" queue_snapshots=%"PRIu64" read_failures=%"PRIu64" callback_failures=%"PRIu64" lost=%"PRIu64"",
 name,result,depth(s),native,d?d->have_final:0,d?d->cubes_total:-1,d?d->fixpoint:-1,d?d->cubes_fix:-1,d?d->flops:-1,d?d->coi:-1,count,
 s->relative_calls,s->relative_sat,s->relative_unsat,s->relative_limit,s->solver_calls,s->solver_sat,s->solver_unsat,s->solver_limit,s->generalize_calls,s->push_calls,s->block_calls,s->obligation_process_calls,obligations(s),d?d->total_checks:0,d?d->total_mismatch:0,d?d->stats_checks:0,d?d->stats_mismatch:0,d?d->cube_ids:0,d?d->po_ids:0,d?d->frame_scans:0,d?d->queue_scans:0,s->read_failures,s->callback_failures,s->lost);
}

static int frame_of_frontier(struct run_state*s,uintptr_t frontier){
 if(frontier==s->seq+120)return -1;
 if(frontier==s->seq+152)return -2; /* pending invariant export set */
 uintptr_t begin=0;if(!read_u64(s->seq+104,&begin))return -3;
 int n=read_i32(s,s->seq,112);
 if(frontier>=begin&&frontier-begin<(uintptr_t)n*32&&(frontier-begin)%32==0)return (int)((frontier-begin)/32);
 return -3;
}
static void removed_relationships(struct run_state*s,uintptr_t vector,uintptr_t front,uint64_t by,uint64_t op,unsigned method,int result){
 uintptr_t data=0,end=0;
 if(!read_u64(vector,&data)||!read_u64(vector+8,&end)||end<data||(end-data)%8||(end-data)/8>DETAIL_MAX_ITEMS){detail_error(s,"subsumption_removed_vector");return;}
 size_t n=(end-data)/8;
 emit(s,"subsumption_result",false,"operation=%"PRIu64" by_cube_id=%"PRIu64" frame=%d method=%u result_known=%u result_bool=%u removed=%zu",op,by,frame_of_frontier(s,front),method,method!=0,method?((unsigned)result&1):0,n);
 for(size_t i=0;i<n;i++){
  uintptr_t cube=0;if(!read_u64(data+i*8,&cube)){detail_error(s,"subsumption_removed_cube");break;}
  uint64_t id=full_cube(s,cube);
  emit(s,"subsumption_edge",false,"operation=%"PRIu64" subsuming_cube_id=%"PRIu64" removed_cube_id=%"PRIu64" frame=%d source=native_removed_vector",op,by,id,frame_of_frontier(s,front));
 }
}

static bool known_sat_solver(struct run_state*s,uintptr_t candidate){
 uintptr_t js=0,solver=0;
 if(read_u64(s->jip+56,&js)&&js&&read_u64(js+120,&solver)&&solver==candidate)return true;
 if(read_u64(s->seq+64,&js)&&js&&read_u64(js+120,&solver)&&solver==candidate)return true;
 if(read_u64(s->seq+72,&solver)&&solver==candidate)return true;
 if(read_u64(s->seq+96,&solver)&&solver==candidate)return true;
 return false;
}
static void sat_call_probe(struct run_state*s,struct hook*h,GumCpuContext*c,bool before,uint64_t owner){
 struct detailed_state*d=ds(s);if(!d||!full_abi())return;
 if(before){
  uintptr_t solver=c->rdi;
  if(!solver||!known_sat_solver(s,solver))return;
  uintptr_t vt=0;if(!read_u64(solver,&vt)||vt!=c->rax)return;
  if(d->sat_depth>=32){detail_error(s,"nested_sat_limit");return;}
  struct sat_inflight*v=&d->sat_stack[d->sat_depth++];
  v->site=h->rva;v->stack=c->rsp;v->owner=owner;v->id=++s->solver_calls;v->query=s->current_relative;v->frame=d->relative_frame;
  v->cube_lits=cube_size(s,d->relative_cube);
  uintptr_t data=0,end=0,cap=0;int count=-1;uint64_t payload=0;
  if(read_u64(c->rsi,&data)&&read_u64(c->rsi+8,&end)&&read_u64(c->rsi+16,&cap)&&end>=data&&cap>=end&&(end-data)%4==0&&(end-data)/4<=DETAIL_MAX_ITEMS){
   count=(int)((end-data)/4);payload=capture_vector_data(s,data,count,"sat_literal_raw");
  }else detail_error(s,"sat_call_assumptions");
  char native[768];native_fields(s,native);
  emit(s,"sat_begin",false,"call=%"PRIu64" relative_query=%"PRIu64" query_kind=%s frame=%d flags=%u depth=%d cube_lits=%d assumptions=%d assumptions_id=%"PRIu64" budget=%d avoid_model=%u native_callsite=%"PRIxPTR" %s",v->id,v->query,v->query?"relative":"other_native_ic3",v->frame,(unsigned)d->relative_flags,depth(s),v->cube_lits,count,payload,(int32_t)c->rdx,(unsigned)c->rcx&255,h->rva,native);
  __atomic_add_fetch(&active_queries,1,__ATOMIC_RELAXED);
  v->start=now_ns();v->cpu=clock_ns(CLOCK_THREAD_CPUTIME_ID);v->process=clock_ns(CLOCK_PROCESS_CPUTIME_ID);
 }else{
  if(!d->sat_depth)return;
  struct sat_inflight*v=&d->sat_stack[d->sat_depth-1];
  if(v->site!=(uintptr_t)h->fixed_flags||v->stack!=c->rsp)return;
  d->sat_depth--;
  uint64_t elapsed=now_ns()-v->start,cpu=clock_ns(CLOCK_THREAD_CPUTIME_ID)-v->cpu,process=clock_ns(CLOCK_PROCESS_CPUTIME_ID)-v->process;
  int result=(int32_t)c->rax;const char*name;
  if(result==P.sat_true){s->solver_sat++;name="sat";}
  else if(result==P.sat_false||result==P.sat_assume){s->solver_unsat++;name="unsat";}
  else{s->solver_limit++;name="limit_or_unknown";}
  char native[768];native_fields(s,native);
  emit(s,"sat_end",false,"call=%"PRIu64" relative_query=%"PRIu64" query_kind=%s result=%s result_raw=%d wall_ns=%"PRIu64" thread_cpu_ns=%"PRIu64" process_cpu_ns=%"PRIu64" elapsed=%.9f frame=%d depth=%d cube_lits=%d native_callsite=%"PRIxPTR" %s",v->id,v->query,v->query?"relative":"other_native_ic3",name,result,elapsed,cpu,process,process/1e9,v->frame,depth(s),v->cube_lits,v->site,native);
  __atomic_sub_fetch(&active_queries,1,__ATOMIC_RELAXED);
 }
}
