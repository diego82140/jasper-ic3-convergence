/* Independent counterparts of the observed Dollar diagnostic contracts.
 * Reads the exact target's state and watches its ORIGINAL validation branches.
 * Never calls a replacement solver, changes a proof field, or infers a pass
 * from a property verdict. Target addresses are guarded by the loaded profile.
 */
static bool parity_target(void){return !strcmp(P.hash,"b5006df1ff1ab23d9effd5eec464b1962a0905da1880aaa8fae574a4a9a81604");}
static bool native_validation_target(void){return parity_target()||!strcmp(P.hash,"e8cbfa93df42061662aaa530125f47d9255ff29b160aa3559d65c706bb24ce1d");}
static void parity_sha(const char*data,size_t n,char out[65]){
 js_sha c={{0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19},0,0,{0}};
 js_update(&c,(const unsigned char*)data,n);uint64_t bits=c.bytes*8;c.b[c.n++]=0x80;
 if(c.n>56){memset(c.b+c.n,0,64-c.n);js_block(&c,c.b);c.n=0;}
 memset(c.b+c.n,0,56-c.n);for(int i=0;i<8;i++)c.b[63-i]=(unsigned char)(bits>>(8*i));js_block(&c,c.b);
 static const char h[]="0123456789abcdef";for(int i=0;i<32;i++){unsigned v=(c.s[i/4]>>(24-8*(i%4)))&255;out[2*i]=h[v>>4];out[2*i+1]=h[v&15];}out[64]=0;
}
static void parity_record(struct run_state*s,const char*family,const char*fmt,...) __attribute__((format(printf,3,4)));
static void parity_record(struct run_state*s,const char*family,const char*fmt,...){
 if(!s||!s->parity_enabled||reporting)return;
 int saved=errno;va_list ap,copy;va_start(ap,fmt);va_copy(copy,ap);int n=vsnprintf(NULL,0,fmt,copy);va_end(copy);
 if(n<0||n>8*1024*1024){va_end(ap);detail_error(s,"parity_record_size");errno=saved;return;}
 size_t prefix=strlen(family);char*line=malloc(prefix+(size_t)n+3);
 if(!line){va_end(ap);detail_error(s,"parity_record_allocation");errno=saved;return;}
 memcpy(line,family,prefix);line[prefix]=' ';vsnprintf(line+prefix+1,(size_t)n+1,fmt,ap);va_end(ap);
 size_t len=prefix+1+(size_t)n;char digest[65];parity_sha(line,len,digest);
 emit(s,"parity_record",false,"family=%s parity_sequence=%"PRIu64" bytes=%zu sha256=%s source=observed_original_engine_state",family,++s->parity_lines,len,digest);
 for(size_t at=0;at<len;at+=512){
  size_t count=len-at;if(count>512)count=512;char encoded[1025];hexbytes((const unsigned char*)line+at,count,encoded);
  emit(s,"parity_record_chunk",false,"parity_sequence=%"PRIu64" offset=%zu bytes=%zu utf8_hex=%s",s->parity_lines,at,count,encoded);
 }
 emit(s,"parity_record_end",false,"parity_sequence=%"PRIu64" bytes=%zu complete=1",s->parity_lines,len);
 line[len]='\n';disk_record(line,len+1);line[len]=0;
 if(!disk_only){
 if(!s->callback_entry)resolve_callback(s);
 if(s->callback_entry){void(*report)(void*,const char*,unsigned,bool)=NULL;memcpy(&report,&s->callback_entry,sizeof report);reporting=true;report((void*)s->callback,line,0,true);reporting=false;}
 else{s->callback_failures++;__atomic_add_fetch(&callback_failures,1,__ATOMIC_RELAXED);}
 }
 free(line);errno=saved;
}
struct parity_text{char*data;size_t n,cap;bool bad;};
static void pt_add(struct parity_text*t,const char*s,size_t n){
 if(t->bad)return;
 if(t->n+n+1<t->n||t->n+n>8*1024*1024){t->bad=true;return;}
 if(t->n+n+1>t->cap){size_t cap=(t->n+n+1)*2;char*p=realloc(t->data,cap);if(!p){t->bad=true;return;}t->data=p;t->cap=cap;}
 memcpy(t->data+t->n,s,n);t->n+=n;t->data[t->n]=0;
}
static void pt_put(struct parity_text*t,const char*s){pt_add(t,s,strlen(s));}
static bool parity_nodes(uintptr_t*base,int32_t*count){
 return read_u64(bias+0x1e3c3f0,base)&&read_bytes(bias+0x1e3c3f8,count,4)&&*count>=0&&*count<0x10000000;
}
static bool parity_children(uint32_t f,uint32_t out[2]){
 uintptr_t nodes;int32_t n;uint32_t index=f>>3;
 if(!parity_nodes(&nodes,&n)||index>=(uint32_t)n)return false;
 return read_bytes(nodes+(uintptr_t)index*8,out,8);
}
static bool parity_formula(struct run_state*s,uintptr_t circ,uint32_t f,struct parity_text*t,unsigned level){
 if(level>10){pt_put(t,"( ... )");return !t->bad;}
 if(!(f&2)){
  if((f|4)==0xfffffffcU){pt_put(t,f&4?"0":"1");return !t->bad;}
  if((f|4)==0xfffffff4U){pt_put(t,f&4?"err":"udf");return !t->bad;}
  uintptr_t table=0,ptr=0;int n=read_i32(s,circ,8);uint32_t index=f>>3;
  if(index>=(uint32_t)n||!read_u64(circ,&table)||!read_u64(table+(uintptr_t)index*8,&ptr)||!ptr)return false;
  unsigned char c;if(!read_bytes(ptr,&c,1))return false;
  if(f&4){if(c=='~')ptr++;else pt_put(t,"~");}
  for(size_t i=0;i<1024*1024;i++){if(!read_bytes(ptr+i,&c,1))return false;if(!c)return !t->bad;pt_add(t,(const char*)&c,1);}
  return false;
 }
 uint32_t child[2];if(!parity_children(f,child))return false;
 pt_put(t,f&4?"~(":"(");if(!parity_formula(s,circ,child[0]&~1U,t,level+1))return false;
 pt_put(t,child[0]&1?"==":"&");if(!parity_formula(s,circ,child[1]&~1U,t,level+1))return false;
 pt_put(t,")");return !t->bad;
}
static bool parity_cube_read(struct run_state*s,uintptr_t cube,uint32_t**values,int*size){
 int n=cube_size(s,cube);uintptr_t ptr;if(n<0||n>10000000||!read_u64(cube,&ptr))return false;
 uint32_t*v=malloc(n?(size_t)n*4:1);if(!v)return false;
 if(n&&!read_bytes(ptr,v,(size_t)n*4)){free(v);return false;}*values=v;*size=n;return true;
}
static bool parity_cube_text(struct run_state*s,uintptr_t circ,const uint32_t*v,int n,int max,struct parity_text*t){
 pt_put(t,"");int shown=n<max?n:max;
 for(int i=0;i<shown;i++){if(i)pt_put(t," ");if(!parity_formula(s,circ,v[i],t,0))return false;}
 if(shown<n){char b[64];snprintf(b,sizeof b," ... +%d",n-shown);pt_put(t,b);}return !t->bad;
}
static uint64_t parity_cube_hash(const uint32_t*v,int n){
 uint64_t hash=0xcbf29ce484222325ULL;
 for(int i=0;i<n;i++)for(int b=0;b<8;b++){hash^=((uint64_t)v[i]>>(8*b))&255;hash*=0x100000001b3ULL;}
 return (hash^(uint64_t)n)*0x100000001b3ULL;
}
static bool parity_support_walk(uint32_t root,unsigned char*support,int nvars,unsigned char*visited,int nnodes){
 /* Iterative DAG walk: no recursion depth limit and no C stack overflow on
  * deeply synthesized expressions. The display formatter has Dollar's own
  * separately documented ten-level presentation cutoff. */
 GArray*pending=g_array_new(FALSE,FALSE,sizeof(uint32_t));g_array_append_val(pending,root);bool okay=true;
 while(pending->len){
  uint32_t f=g_array_index(pending,uint32_t,pending->len-1);g_array_set_size(pending,pending->len-1);
  if(!(f&2)){
   if((f|4)==0xfffffffcU||(f|4)==0xfffffff4U)continue;
   unsigned index=f>>3;if(index>=(unsigned)nvars){okay=false;break;}support[index]=1;continue;
  }
  unsigned index=f>>3;if(index>=(unsigned)nnodes){okay=false;break;}if(visited[index])continue;visited[index]=1;
  uint32_t child[2];if(!parity_children(f,child)){okay=false;break;}
  child[0]&=~1U;child[1]&=~1U;g_array_append_val(pending,child[1]);g_array_append_val(pending,child[0]);
 }
 g_array_free(pending,TRUE);return okay;
}
static unsigned char*parity_support(struct run_state*s,uintptr_t circ,int*nout){
 uintptr_t nodes=0,props=0,nexts=0;int32_t nn=0;
 int nv=read_i32(s,circ,24),nl=read_i32(s,circ,16),np=read_i32(s,s->seq,224);
 if(nv<0||nl<0||nl>nv||nv>10000000||np<0||np>10000000||!parity_nodes(&nodes,&nn)||!read_u64(s->seq+216,&props)||!read_u64(circ+32,&nexts))return NULL;
 unsigned char*set=calloc(nv?nv:1,1),*direct=calloc(nv?nv:1,1),*seen=calloc(nn?nn:1,1);
 if(!set||!direct||!seen)goto fail;
 for(int i=0;i<np;i++){uint32_t f;if(!read_bytes(props+(uintptr_t)i*4,&f,4)||!parity_support_walk(f,set,nv,seen,nn))goto fail;}
 memcpy(direct,set,nv);memset(seen,0,nn);
 /* Native Dollar target lens: support of active properties plus one next-state
  * expansion of latches in their direct support; NOT transitive-closure COI. */
 for(int i=0;i<nl;i++)if(direct[i]){uint32_t f;if(!read_bytes(nexts+(uintptr_t)i*4,&f,4)||!parity_support_walk(f,set,nv,seen,nn))goto fail;}
 free(direct);free(seen);*nout=nv;return set;
fail:free(set);free(direct);free(seen);return NULL;
}
static int parity_project(const uint32_t*in,int n,const unsigned char*support,int nv,uint32_t*out){
 int count=0;for(int i=0;i<n;i++){unsigned f=in[i],idx=f>>3;if(f&2)return -1;if(idx<(unsigned)nv&&support[idx])out[count++]=f;}return count;
}
static void parity_cti(struct run_state*s,int frame,uintptr_t source,uintptr_t predecessor){
 if(!s->parity_enabled)return;
 int sample=read_i32(s,s->seq,P.pre_other_offset);
 if(sample>8&&(sample&(sample-1)))return;
 uintptr_t circ=0,props=0;uint32_t*sv=NULL,*pv=NULL,*st=NULL,*pt=NULL;int sn=0,pn=0,nv=0;
 struct parity_text state={0},target={0},sourcestate={0},prop={0};unsigned char*support=NULL;
 if(!read_u64(s->jip+64,&circ)||!parity_cube_read(s,source,&sv,&sn)||!parity_cube_read(s,predecessor,&pv,&pn))goto fail;
 st=malloc(sn?(size_t)sn*4:1);pt=malloc(pn?(size_t)pn*4:1);support=parity_support(s,circ,&nv);if(!st||!pt||!support)goto fail;
 int tn=parity_project(pv,pn,support,nv,pt),stn=parity_project(sv,sn,support,nv,st);if(tn<0||stn<0)goto fail;
 if(!parity_cube_text(s,circ,pv,pn,24,&state)||!parity_cube_text(s,circ,pt,tn,64,&target)||!parity_cube_text(s,circ,st,stn,64,&sourcestate))goto fail;
 int np=read_i32(s,s->seq,224),index=-1;uint32_t active=(uint32_t)read_i32(s,s->seq,264)^4;
 if(!read_u64(s->seq+216,&props))goto fail;
 for(int i=0;i<np;i++){uint32_t f;if(!read_bytes(props+(uintptr_t)i*4,&f,4))goto fail;if(f==active){index=i;break;}}
 if(index>=0){if(!parity_formula(s,circ,active,&prop,0))goto fail;}
 else pt_put(&prop,"?");
 if(prop.n>256){size_t old=prop.n;prop.n=256;prop.data[256]=0;char tail[80];snprintf(tail,sizeof tail," ... +%zu chars",old-256);pt_put(&prop,tail);}
 parity_record(s,"IC3_CTI","phase=predecessor sample=%d depth=%d frame=%d active_property_index=%d active_property_fingerprint=%016"PRIx64" active_property=\"%s\" source_lits=%d predecessor_lits=%d target_lits=%d target_fingerprint=%016"PRIx64" target_state=\"%s\" source_target_lits=%d source_target_fingerprint=%016"PRIx64" source_target_state=\"%s\" state=\"%s\"",sample,depth(s),frame,index,(uint64_t)active,prop.data,sn,pn,tn,parity_cube_hash(pt,tn),target.data,stn,parity_cube_hash(st,stn),sourcestate.data,state.data);
 goto done;
fail:detail_error(s,"Dollar_CTI_decode");
done:free(sv);free(pv);free(st);free(pt);free(support);free(state.data);free(target.data);free(sourcestate.data);free(prop.data);
}
static void parity_aggregate_final(struct run_state*s){
 if(!s->parity_enabled)return;
 emit(s,"dollar_scalar_extension",false,"generalize_success=%"PRIu64" generalized_lits=%"PRIu64" relative_sat=%"PRIu64" relative_unsat=%"PRIu64" relative_limit=%"PRIu64,s->successful_generalizations,s->removed_generalization_literals,s->relative_sat,s->relative_unsat,s->relative_limit);
}
static void parity_validation_enter(struct run_state*s,uintptr_t props){
 if(!native_validation_target())return;
 s->validation_active=true;s->validation_failed=false;s->validation_inconclusive=false;s->validation_props=props;
 s->validation_base_count=s->validation_step_count=s->validation_property_count=0;
 s->validation_base_closed=s->validation_step_closed=s->validation_property_closed=false;
 emit(s,"native_validation_begin",false,"context=original_ic_fixpoint_validation props=%d not_inferred_from_final_verdict=1",cube_size(s,props));
}
static const char*validation_check_outcome(struct run_state*s){
 return s->validation_failed?"refuted_local":s->validation_inconclusive?"inconclusive":"pass";
}
static void parity_validation_stage(struct run_state*s,enum hook_kind k){
 if(k==H_VALBASE&&!s->validation_base_closed){
  s->validation_base_closed=true;emit(s,"native_validation_stage",false,"stage=base result=%s checks=%"PRIu64,validation_check_outcome(s),s->validation_base_count);if(!s->validation_failed&&!s->validation_inconclusive)parity_record(s,"IC3_VALIDATION","phase=base result=pass clauses=%"PRIu64,s->validation_base_count);
 }else if(k==H_VALSTEP&&!s->validation_step_closed){
  s->validation_step_closed=true;emit(s,"native_validation_stage",false,"stage=step result=%s checks=%"PRIu64,validation_check_outcome(s),s->validation_step_count);if(!s->validation_failed&&!s->validation_inconclusive)parity_record(s,"IC3_VALIDATION","phase=step result=pass clauses=%"PRIu64,s->validation_step_count);
 }else if(k==H_VALPROPERTY&&!s->validation_property_closed){
  s->validation_property_closed=true;emit(s,"native_validation_stage",false,"stage=property result=%s checks=%"PRIu64,validation_check_outcome(s),s->validation_property_count);if(!s->validation_failed&&!s->validation_inconclusive)parity_record(s,"IC3_VALIDATION","phase=property result=pass properties=%d",cube_size(s,s->validation_props));
 }
}
static void parity_validation_solver(struct run_state*s,struct hook*h,GumCpuContext*ctx,bool before){
 if(before)return;
 int r=(int)(int32_t)ctx->rax;const char*stage=NULL;
 if(h->rva==0x16dec61||h->rva==0xc814fa){
  s->validation_step_count++;stage="step";
 }else if(h->rva==0x16df002||h->rva==0xc818a3){
  s->validation_property_count++;stage="property";
 }
 const char*outcome=(r==P.sat_false||r==P.sat_assume)?"unsat":r==P.sat_true?"sat_local":"limit_or_unknown";
 if(stage&&r==P.sat_true){s->validation_failed=true;parity_record(s,"IC3_VALIDATION","phase=%s result=fail reason=%s scope=local_validation_check native_reachable_cex=0",stage,!strcmp(stage,"step")?"non-inductive-clause":"not-implied-by-fixpoint");}
 else if(stage&&r!=P.sat_false&&r!=P.sat_assume){s->validation_inconclusive=true;parity_record(s,"IC3_VALIDATION","phase=%s result=inconclusive reason=resource_limit_or_unknown result_raw=%d",stage,r);}
 emit(s,"native_validation_solver",false,"callsite=%"PRIxPTR" result_raw=%d result=%s real_solver=1 native_reachable_cex=0",h->rva,r,outcome);
}
static void parity_validation_leave(struct run_state*s){
 s->validation_active=false;
 bool closed=s->validation_base_closed&&s->validation_step_closed&&s->validation_property_closed;
 emit(s,"native_validation_end",false,"base_checks=%"PRIu64" step_checks=%"PRIu64" property_checks=%"PRIu64" all_three_native_success_boundaries=%u failed=%u inconclusive=%u outcome=%s",s->validation_base_count,s->validation_step_count,s->validation_property_count,closed,s->validation_failed,s->validation_inconclusive,s->validation_failed||s->validation_inconclusive?validation_check_outcome(s):closed?"pass":"incomplete");
 if(s->await_validation){s->final_validation_observed=true;s->await_validation=false;s->pending_seal=true;}
}

/* Native lens selection follows map-key order and list order. Disabled nodes
 * count toward native heap size but never toward focus or active-level counts. */
struct parity_po{uintptr_t address,cube,parent;uint32_t bits;int cex,level,literals;};
static bool parity_po_read(struct run_state*s,uintptr_t address,struct parity_po*out){
 unsigned char b[24];if(!address||!read_bytes(address,b,sizeof b))return false;
 out->address=address;memcpy(&out->bits,b,4);memcpy(&out->cex,b+4,4);memcpy(&out->cube,b+8,8);memcpy(&out->parent,b+16,8);
 out->level=(int32_t)out->bits>>2;out->literals=cube_size(s,out->cube);
 return out->literals>=0 && out->level>=-1 && out->cex>=0;
}
static uint64_t parity_seen(struct detailed_state*d,int map,uint64_t key){
 if(!d->parity_counts[map])d->parity_counts[map]=g_hash_table_new_full(g_int64_hash,g_int64_equal,free,free);
 uint64_t*value=g_hash_table_lookup(d->parity_counts[map],&key);
 if(value)return ++*value;
 uint64_t*k=malloc(8),*v=malloc(8);if(!k||!v){free(k);free(v);return 0;}*k=key;*v=1;g_hash_table_insert(d->parity_counts[map],k,v);return 1;
}
static bool parity_chain(struct run_state*s,uintptr_t ptr,struct parity_text*out){
 unsigned n=0;pt_put(out,"");
 while(ptr&&n<8){
  struct parity_po po;uint32_t*values=NULL;int size=0;
  if(!parity_po_read(s,ptr,&po)||!parity_cube_read(s,po.cube,&values,&size))return false;
  char part[128];snprintf(part,sizeof part,"%sL%d/%s/C%d/H%016"PRIx64,n?" <- ":"",po.level,po.bits&1?"may":"must",po.cex,parity_cube_hash(values,size));free(values);pt_put(out,part);
  ptr=po.parent;n++;
 }
 if(ptr)pt_put(out," <- ...");
 return !out->bad;
}
static bool parity_focus(struct run_state*s,uintptr_t circ,const char*queue,const char*role,const struct parity_po*po,unsigned sample,const unsigned char*support,int nv){
 struct detailed_state*d=ds(s);uint32_t*v=NULL,*proj=NULL,*pv=NULL,*pproj=NULL;int n=0,pn=0,tn=0,ptn=0;
 struct parity_text state={0},target={0},parent_target={0},chain={0};bool ok=false;
 if(!parity_cube_read(s,po->cube,&v,&n))goto done;
 proj=malloc(n?(size_t)n*4:1);if(!proj)goto done;
 tn=parity_project(v,n,support,nv,proj);if(tn<0)goto done;
 if(po->parent){struct parity_po parent;if(!parity_po_read(s,po->parent,&parent)||!parity_cube_read(s,parent.cube,&pv,&pn))goto done;}
 pproj=malloc(pn?(size_t)pn*4:1);if(!pproj)goto done;
 ptn=parity_project(pv,pn,support,nv,pproj);if(ptn<0)goto done;
 if(!parity_cube_text(s,circ,v,n,24,&state)||!parity_cube_text(s,circ,proj,tn,64,&target)||!parity_cube_text(s,circ,pproj,ptn,64,&parent_target)||!parity_chain(s,po->address,&chain))goto done;
 uint64_t hash=parity_cube_hash(v,n),thash=parity_cube_hash(proj,tn),phash=parity_cube_hash(pproj,ptn);
 for(int i=0;i<n;i++)v[i]&=~4U;
 uint64_t supporthash=parity_cube_hash(v,n);
 uint64_t seen=parity_seen(d,0,hash),ss=parity_seen(d,1,supporthash),ts=parity_seen(d,2,thash),ps=parity_seen(d,3,phash);
 if(!seen||!ss||!ts||!ps)goto done;
 parity_record(s,"IC3_OBLIGATION_FOCUS","sample=%u queue=%s role=%s frame=%d type=%s cex_depth=%d cube_lits=%d fingerprint=%016"PRIx64" snapshots_seen=%"PRIu64" support_fingerprint=%016"PRIx64" support_snapshots_seen=%"PRIu64" target_lits=%d target_fingerprint=%016"PRIx64" target_snapshots_seen=%"PRIu64" target_state=\"%s\" parent_target_lits=%d parent_target_fingerprint=%016"PRIx64" parent_target_snapshots_seen=%"PRIu64" parent_target_state=\"%s\" state=\"%s\" parent_chain=\"%s\"",sample,queue,role,po->level,po->bits&1?"may":"must",po->cex,n,hash,seen,supporthash,ss,tn,thash,ts,target.data,ptn,phash,ps,parent_target.data,state.data,chain.data);
 ok=true;
done:free(v);free(proj);free(pv);free(pproj);free(state.data);free(target.data);free(parent_target.data);free(chain.data);return ok;
}
static bool parity_queue(struct run_state*s,uintptr_t circ,uintptr_t heap,const char*name,unsigned sample,const unsigned char*support,int nv){
 uintptr_t root=0,at=0;int total=read_i32(s,heap,4);if(total<0||total>10000000||!read_u64(heap+32,&root))return false;
 GArray*stack=g_array_new(FALSE,FALSE,sizeof(uintptr_t));GArray*entries=g_array_new(FALSE,FALSE,sizeof(struct parity_po));GHashTable*visited=g_hash_table_new(g_direct_hash,g_direct_equal);
 struct parity_text levels={0};unsigned active=0,disabled=0,may=0;int next=-1,deep=-1,small=-1;bool ok=false;at=root;
 while(at||stack->len){
  while(at){if(g_hash_table_contains(visited,(gpointer)at))goto done;g_hash_table_add(visited,(gpointer)at);g_array_append_val(stack,at);if(!read_u64(at+16,&at))goto done;}
  at=g_array_index(stack,uintptr_t,stack->len-1);g_array_set_size(stack,stack->len-1);
  uintptr_t node=0,right=0;int level=read_i32(s,at,32);if(!read_u64(at+40,&node)||!read_u64(at+24,&right))goto done;
  unsigned level_count=0;
  while(node!=at+40){
   if(entries->len>=(unsigned)total)goto done;
   uintptr_t ptr=0,nxt=0;if(!read_u64(node+16,&ptr)||!read_u64(node,&nxt)||nxt==node)goto done;
   struct parity_po po;if(!parity_po_read(s,ptr,&po))goto done;
   int index=(int)entries->len;g_array_append_val(entries,po);
   if(po.bits&2)disabled++;
   else{
    active++;level_count++;may+=(po.bits&1)!=0;
    if(next<0)next=index;
    if(deep<0||po.cex>g_array_index(entries,struct parity_po,deep).cex)deep=index;
    if(small<0||po.literals<g_array_index(entries,struct parity_po,small).literals||(po.literals==g_array_index(entries,struct parity_po,small).literals&&po.cex<g_array_index(entries,struct parity_po,small).cex))small=index;
   }
   node=nxt;
  }
  if(level_count){char text[80];snprintf(text,sizeof text,"%s%d:%u",levels.n?",":"",level,level_count);pt_put(&levels,text);}
  at=right;
 }
 if(entries->len!=(unsigned)total)goto done;
 if(!levels.n)pt_put(&levels,"-");
 parity_record(s,"IC3_OBLIGATION_QUEUE","sample=%u queue=%s active=%u disabled=%u may=%u must=%u levels=\"%s\"",sample,name,active,disabled,may,active-may,levels.data);
 if(next>=0){
  int candidates[3]={next,deep,small};const char*role_names[3]={"next","deepest","smallest"};
  for(int i=0;i<3;i++){
   bool prior=false;for(int k=0;k<i;k++)if(candidates[k]==candidates[i])prior=true;if(prior)continue;
   char role[64]={0};for(int k=i;k<3;k++)if(candidates[k]==candidates[i]){if(*role)strcat(role,"+");strcat(role,role_names[k]);}
   if(!parity_focus(s,circ,name,role,&g_array_index(entries,struct parity_po,candidates[i]),sample,support,nv))goto done;
  }
 }
 ok=true;
done:free(levels.data);g_array_free(stack,TRUE);g_array_free(entries,TRUE);g_hash_table_destroy(visited);return ok;
}
static void parity_lens(struct run_state*s){
 struct detailed_state*d=ds(s);if(!d||!d->heap)return;
 unsigned sample=(unsigned)++d->lens_samples;if(sample>8&&(sample&(sample-1)))return;
 uintptr_t circ=0,props=0;int nv=0,index=-1;unsigned char*support=NULL;
 if(!read_u64(s->jip+64,&circ)||!read_u64(s->seq+216,&props))goto fail;
 uint32_t active=(uint32_t)read_i32(s,s->seq,264)^4;int n=read_i32(s,s->seq,224);
 if(n<0||n>10000000)goto fail;
 for(int i=0;i<n;i++){uint32_t f;if(!read_bytes(props+(uintptr_t)i*4,&f,4))goto fail;if(f==active){index=i;break;}}
 support=parity_support(s,circ,&nv);if(!support)goto fail;
 char phash[32];if(index<0)strcpy(phash,"-");else snprintf(phash,sizeof phash,"%016"PRIx64,(uint64_t)active);
 parity_record(s,"IC3_OBLIGATION_LENS","sample=%u depth=%d frontier=%d active_property_index=%d active_property_fingerprint=%s short=%d long=%d",sample,depth(s),read_i32(s,s->seq,P.k_offset),index,phash,read_i32(s,d->heap,52),read_i32(s,d->heap,116));
 if(!parity_queue(s,circ,d->heap+48,"short",sample,support,nv)||!parity_queue(s,circ,d->heap+112,"long",sample,support,nv))goto fail;
 free(support);return;
fail:free(support);detail_error(s,"Dollar_obligation_lens_decode");
}

static void parity_configuration(struct run_state*s){
 if(!s->parity_enabled)return;
 uintptr_t cfg=0;unsigned char quip=255,abs=255,satelite=255;
 if(!read_u64(s->seq,&cfg)||!read_bytes(cfg+33,&quip,1)||!read_bytes(cfg+32,&abs,1)||!read_bytes(cfg+34,&satelite,1)||quip>1||abs>1||satelite>1){detail_error(s,"native_IC3_configuration");return;}
 emit(s,"native_ic3_configuration",false,"engine_index=%d restart_mode=%d quip_mode=%u abstraction_mode=%u satelite=%u config_source=read_only_native_IcConfig m4_quip_serialization_key=166",read_i32(s,cfg,0),read_i32(s,cfg,4),quip,abs,satelite);
}
