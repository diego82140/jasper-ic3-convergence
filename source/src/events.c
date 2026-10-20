/* Marker-independent IC3 observer. No Jasper headers or logging-site addresses.
 * Original arguments, return values, object fields and debug selectors are never
 * modified. All IC3_STATS strings and observer counters are owned by this DSO.
 * Profile locations and ABI decoders must be derived/qualified for the exact ELF.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "frida-gum.h"
#ifndef GUM_NATIVE_UNWIND_RETURN_RESTORE
#error "Build requires the qualified producer Gum fork and its runtime-status API"
#endif
#include "sha256.h"
#include <dlfcn.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <link.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <zlib.h>

#define MAX_HOOKS 128
#define MAX_RUNS 64
#define MAX_RECORD 4096
#define UNAVAILABLE (-1)
enum hook_kind { H_INIT,H_RELATIVE,H_SAT,H_PUSH,H_BLOCK,H_OBLIGATION,H_GENERALIZE,H_STATS,H_RUN,H_FRAME,H_GETSTATS,H_TOTALCUBES,H_ADDCUBE,H_SUBSUMPTION,H_QUEUEPUSH,H_PODISPOSE,H_TRACE,H_SAMPLE,H_GETCEX,H_QUEUEUNLINK,H_FRONTREMOVE,H_SATBEFORE,H_SATAFTER,H_PREDECESSOR,H_VALIDATION,H_ISINITIAL,H_VALBASE,H_VALSTEP,H_VALPROPERTY,H_LENS };
static const char *kind_names[]={"init","relative","sat","push","block","obligation","generalize","stats","run","frame","getstats","totalcubes","addcube","subsumption","queuepush","podispose","trace","sample","getcex","queueunlink","frontremove","satbefore","satafter","predecessor","validation","isinitial","valbase","valstep","valproperty","lens"};
struct hook {
 enum hook_kind kind; uintptr_t rva; int jip_arg,seq_arg,frame_arg,flags_arg,cube_arg,fixed_flags;
 unsigned char guard[32]; unsigned guard_len; GumInvocationListener *listener;
};
struct profile {
 char hash[65]; unsigned callback,report_slot,details; int k_offset,obligations_offset;
 int pre_bad_offset,pre_other_offset,generalize_offset,calls_offset;
 unsigned cube_data,cube_size,cube_item;
 int rel_true,rel_false,rel_unknown,sat_true,sat_false,sat_assume,valid,cex;
 struct hook hooks[MAX_HOOKS]; unsigned nh;
};
struct detailed_state;
struct run_ledger;
struct run_state {
 struct detailed_state *detail;
 bool parity_enabled,await_validation,validation_active,validation_failed;
 bool final_validation_expected,final_validation_observed,final_validation_aborted,validation_missing,validation_inconclusive;
 uint64_t validation_abort_event;
 bool validation_base_closed,validation_step_closed,validation_property_closed;
 uint64_t validation_base_count,validation_step_count,validation_property_count,parity_lines;
 uintptr_t validation_props; uint64_t successful_generalizations,removed_generalization_literals;
 struct run_ledger *ledger;
 bool contract_emitted,sealed; char chain[65];
 bool pending_seal,completion_tail;
 bool run_unwound;
 uint64_t run_abort_event;
 uint64_t activation_begins,activation_returns,activation_aborts,activation_live,observer_errors,native_unwind_aborts;
 uint64_t context_revision,model_epoch,current_operation,emit_wall_ns,final_event; int current_kind;
 uintptr_t jip,seq; uint64_t id; bool live; unsigned rel_depth;
 uint64_t relative_calls,relative_sat,relative_unsat,relative_limit,relative_other;
 uint64_t solver_calls,solver_sat,solver_unsat,solver_limit,solver_other;
 uint64_t generalize_calls,push_calls,block_calls,obligation_process_calls,frame_calls;
 uint64_t current_relative,records,lost,read_failures,callback_failures;
 int last_depth,max_obligations; uintptr_t callback,callback_entry;
};
struct invocation {
 struct run_state *state,*previous;
 uintptr_t cube; uint64_t id,start,previous_relative;
 int frame,flags,before_size,result; bool enabled,suppressed,pending_front_binding;
 bool semantic_scope; uint64_t parent_operation,input_cube_id,entry_revision; int parent_kind;
 uintptr_t pointers[6],heap,previous_heap; uint64_t cpu_start,process_start,operation,previous_generalize,po_id;
 uint64_t activation_token,run_generation;
};
static struct profile P;
static uintptr_t bias;
static uint64_t next_id,instances,generated_records,forwarded_records,read_failures,unknown_results;
static uint64_t dropped_records,callback_failures,active_queries;
static uint64_t unbound_hook_calls,ambiguous_seq_bindings;
static uint64_t unbound_hook_kinds[H_LENS+1];
static uint64_t native_reports_redirected;
static char capture_id[33];
static _Thread_local struct run_state runs[MAX_RUNS];
static _Thread_local struct run_state *current;
static _Thread_local bool reporting;
static _Thread_local int evidence_fd=-1;
static _Thread_local pid_t evidence_pid;
static uint64_t record_limit=UINT64_MAX;
static bool include_cubes=true;
static bool disk_only=false;
static bool compress_disk=false;
struct compressed_sink {struct compressed_sink*next;gzFile stream;};
static struct compressed_sink*sink_head;
static pthread_mutex_t sink_mutex=PTHREAD_MUTEX_INITIALIZER;
static _Thread_local struct compressed_sink*evidence_sink;
static bool frame_inline_enabled=false;
static bool frame_chunks_enabled=false; /* Opt-in until native/storage qualification. */
static bool full_snapshots=false; /* Default: native deltas plus named checkpoints. */
static GumInterceptor *interceptor;

static _Thread_local int memory_fd=-1;
static _Thread_local pid_t memory_pid;
static bool read_bytes(uintptr_t address,void *out,size_t size) {
 if(!address || !size || address>UINTPTR_MAX-size)return false;
 pid_t pid=getpid();
 if(memory_pid!=pid){if(memory_fd>=0)close(memory_fd);memory_fd=-1;memory_pid=pid;}
 if(memory_fd<0)memory_fd=open("/proc/self/mem",O_RDONLY|O_CLOEXEC);
 if(memory_fd<0)return false;
 ssize_t n;do{n=pread(memory_fd,out,size,(off_t)address);}while(n<0&&errno==EINTR);
 return n==(ssize_t)size;
}
static bool read_u64(uintptr_t a,uintptr_t *out){return read_bytes(a,out,sizeof *out);}
static int read_i32(struct run_state*s,uintptr_t base,int off){
 int32_t n;
 if(!base || off<0 || !read_bytes(base+(unsigned)off,&n,sizeof n)){
  if(off>=0){if(s)s->read_failures++;__atomic_add_fetch(&read_failures,1,__ATOMIC_RELAXED);}return UNAVAILABLE;
 }
 return n;
}
static uint64_t now_ns(void){struct timespec t;if(clock_gettime(CLOCK_MONOTONIC,&t))return 0;return (uint64_t)t.tv_sec*1000000000ULL+t.tv_nsec;}
static int exec_test(struct dl_phdr_info *i,size_t ignored,void*arg){
 (void)ignored;uintptr_t a=*(uintptr_t*)arg;
 for(unsigned k=0;k<i->dlpi_phnum;k++){
  const ElfW(Phdr)*p=&i->dlpi_phdr[k];
  if(p->p_type==PT_LOAD&&(p->p_flags&PF_X)&&a>=i->dlpi_addr+p->p_vaddr&&a<i->dlpi_addr+p->p_vaddr+p->p_memsz)return 1;
 }return 0;
}
static bool executable(uintptr_t a){return dl_iterate_phdr(exec_test,&a)==1;}
static void disk_failure(void){
 __atomic_add_fetch(&dropped_records,1,__ATOMIC_RELAXED);
 if(disk_only){const char msg[]="[JIPSTATS] disk capture failed; worker stopped (no complete capture)\n";write(2,msg,sizeof msg-1);_exit(74);}
}
static void disk_record(const char *line,size_t length){
 pid_t pid=getpid();
 if(evidence_pid!=pid){if(evidence_fd>=0)close(evidence_fd);evidence_fd=-1;evidence_pid=pid;}
 if(evidence_fd<0){
  const char *dir=getenv("JIPSTATS_EVIDENCE_DIR");if(!dir||!*dir)return;
  char path[PATH_MAX];int n=snprintf(path,sizeof path,"%s/events-%ld-%ld.log%s",dir,(long)pid,(long)syscall(SYS_gettid),compress_disk?".gz":"");
  if(n<0||(size_t)n>=sizeof path){disk_failure();return;}
  evidence_fd=open(path,O_WRONLY|O_CREAT|O_APPEND|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK,0600);
  struct stat st;if(evidence_fd>=0&&(fstat(evidence_fd,&st)||!S_ISREG(st.st_mode))){close(evidence_fd);evidence_fd=-1;}
 }
 if(evidence_fd<0){disk_failure();return;}
 if(compress_disk){
  if(!evidence_sink){
   evidence_sink=calloc(1,sizeof *evidence_sink);if(!evidence_sink){disk_failure();return;}
   evidence_sink->stream=gzdopen(evidence_fd,"ab1");if(!evidence_sink->stream){disk_failure();return;}
   pthread_mutex_lock(&sink_mutex);evidence_sink->next=sink_head;sink_head=evidence_sink;pthread_mutex_unlock(&sink_mutex);
  }
  if(gzwrite(evidence_sink->stream,line,(unsigned)length)!=(int)length)disk_failure();
  return;
 }
 size_t pos=0;while(pos<length){ssize_t n=write(evidence_fd,line+pos,length-pos);if(n<0&&errno==EINTR)continue;if(n<=0){disk_failure();break;}pos+=(size_t)n;}
}
static void flush_disk(void){
 /* A native run seal must survive an orchestrator stopping this engine before
  * ELF destructors run. Finish this member now; zlib starts another member on
  * the next gzwrite without retaining or replaying any event history. */
 if(evidence_sink&&gzflush(evidence_sink->stream,Z_FINISH)!=Z_OK)disk_failure();
 if(disk_only&&evidence_fd>=0&&fdatasync(evidence_fd))disk_failure();
}
static void close_disk_sinks(void){
 pthread_mutex_lock(&sink_mutex);
 for(struct compressed_sink*p=sink_head;p;p=p->next){if(gzclose(p->stream)!=Z_OK)disk_failure();p->stream=NULL;}
 pthread_mutex_unlock(&sink_mutex);
}
static void diagnostic(const char *fmt,...){
 int saved=errno;char body[2800],line[3200];va_list args;va_start(args,fmt);vsnprintf(body,sizeof body,fmt,args);va_end(args);
 int n=snprintf(line,sizeof line,"[JIPSTATS] pid=%ld backend=events %s\n",(long)getpid(),body);
 if(n>0&&(size_t)n<sizeof line){disk_record(line,(size_t)n);fwrite(line,1,(size_t)n,stderr);}
 errno=saved;
}
/* Atlas also has a built-in, sampled IC3 display producer. Route its messages
 * losslessly to the archive; leave every non-IC3 native report unchanged.
 * This replaces only the diagnostic report transport, never a proof routine.
 */
struct native_report_route {uintptr_t entry;gpointer original;};
static struct native_report_route native_routes[16];
static unsigned native_route_count;
static pthread_mutex_t native_route_mutex=PTHREAD_MUTEX_INITIALIZER;
static bool native_archive_text(const char*text){
 if(!text||strncmp(text,"IC3_",4))return false;
 int saved=errno;const char*p=text;
 /* Separate the native display's IC3_STATS namespace from schema-2 events.
  * Prefix every native line; retain its entire text, with no record cap.
  */
 do{
  const char*end=strchr(p,'\n');size_t n=end?(size_t)(end-p):strlen(p);
  char prefix[256];int z=snprintf(prefix,sizeof prefix,"NATIVE_IC3_REPORT capture=%s pid=%ld tid=%ld run=%"PRIu64" text=",capture_id,(long)getpid(),(long)syscall(SYS_gettid),current?current->id:0);
  if(z<=0||(size_t)z>=sizeof prefix){disk_failure();return true;}
  disk_record(prefix,(size_t)z);disk_record(p,n);disk_record("\n",1);
  if(!end||!end[1])break;
  p=end+1;
 }while(true);
 __atomic_add_fetch(&native_reports_redirected,1,__ATOMIC_RELAXED);errno=saved;return true;
}
static void native_report_disk(void*object,const char*text){
 GumInvocationContext*ctx=gum_interceptor_get_current_invocation();
 struct native_report_route*route=gum_invocation_context_get_replacement_data(ctx);
 if(native_archive_text(text))return;
 void(*original)(void*,const char*)=NULL;memcpy(&original,&route->original,sizeof original);original(object,text);
}
static void native_report_text_disk(const char*text){
 GumInvocationContext*ctx=gum_interceptor_get_current_invocation();
 struct native_report_route*route=gum_invocation_context_get_replacement_data(ctx);
 if(native_archive_text(text))return;
 void(*original)(const char*)=NULL;memcpy(&original,&route->original,sizeof original);original(text);
}
static void route_native_report(uintptr_t fn,gpointer replacement){
 if(!disk_only||strcmp(P.hash,"690e3ca961c62999509196ddb8a7f94a1707c6b129fa6f392f25b038206dad47"))return;
 pthread_mutex_lock(&native_route_mutex);
 for(unsigned i=0;i<native_route_count;i++)if(native_routes[i].entry==fn){pthread_mutex_unlock(&native_route_mutex);return;}
 if(native_route_count>=16){pthread_mutex_unlock(&native_route_mutex);disk_failure();return;}
 struct native_report_route*route=&native_routes[native_route_count];route->entry=fn;
 GumInterceptor*interceptor=gum_interceptor_obtain();gpointer original=NULL;
 GumReplaceOptions options={0};options.replacement_data=route;
 GumReplaceReturn rc=gum_interceptor_replace(interceptor,(gpointer)fn,replacement,&original,&options);
 if(rc==GUM_REPLACE_OK){route->original=original;native_route_count++;}
 g_object_unref(interceptor);pthread_mutex_unlock(&native_route_mutex);
 if(rc!=GUM_REPLACE_OK){diagnostic("native_IC3_disk_route_failed rc=%d",rc);disk_failure();}
 else diagnostic("native_IC3_disk_route=enabled scope=builtin_display_projection_not_full_native_state");
}
static void resolve_callback(struct run_state*s){
 uintptr_t cb=0,vt=0,fn=0;
 if(read_u64(s->jip+P.callback,&cb)&&read_u64(cb,&vt)&&read_u64(vt+P.report_slot*sizeof(void*),&fn)&&executable(fn)){
  s->callback=cb;s->callback_entry=fn;
  if(disk_only&&!strcmp(P.hash,"690e3ca961c62999509196ddb8a7f94a1707c6b129fa6f392f25b038206dad47")){
   /* Native built-in renderer uses Jip+472, callback slot 0, two arguments;
    * its optimized default branch calls the pure puts/fflush helper directly.
    * Reviewed call sites cbf079..cbf0a1 and cbf23e..cbf243 establish that ABI.
    */
   uintptr_t native_cb=0,native_vt=0,native_fn=0;
   static const unsigned char guard[]={0x48,0x83,0xec,0x08,0xe8,0x47,0xca,0x7b,0xff,0x48,0x8b,0x05,0x90,0xca,0x23,0x01};unsigned char actual[sizeof guard];
   if(!read_bytes(bias+0xca6390,actual,sizeof actual)||memcmp(actual,guard,sizeof guard)||!read_u64(s->jip+472,&native_cb)||!read_u64(native_cb,&native_vt)||!read_u64(native_vt,&native_fn)||!executable(native_fn)){disk_failure();return;}
   route_native_report(native_fn,(gpointer)native_report_disk);
   route_native_report(bias+0xca6390,(gpointer)native_report_text_disk);
  }
 }
}
/* An unkeyed hash chain detects damaged/truncated captures, not malicious forgery. */
static void chain_hash(const char previous[65],const char*text,size_t n,char out[65]){
 js_sha c={{0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19},0,0,{0}};
 unsigned char seed[32]={0};
 if(previous[0])for(int i=0;i<32;i++){unsigned v=0;unsigned a=previous[2*i],b=previous[2*i+1];v=((a<='9'?a-'0':a-'a'+10)<<4)|(b<='9'?b-'0':b-'a'+10);seed[i]=(unsigned char)v;}
 js_update(&c,seed,32);js_update(&c,(const unsigned char*)text,n);
 uint64_t bits=c.bytes*8;c.b[c.n++]=0x80;
 if(c.n>56){memset(c.b+c.n,0,64-c.n);js_block(&c,c.b);c.n=0;}
 memset(c.b+c.n,0,56-c.n);for(int i=0;i<8;i++)c.b[63-i]=(unsigned char)(bits>>(8*i));js_block(&c,c.b);
 static const char h[]="0123456789abcdef";for(int i=0;i<32;i++){unsigned v=(c.s[i/4]>>(24-8*(i%4)))&255;out[2*i]=h[v>>4];out[2*i+1]=h[v&15];}out[64]=0;
}
struct run_ledger{struct run_ledger*next;uint64_t run,events;pid_t tid;bool sealed;char tip[65];};
static struct run_ledger*ledger_head;static pthread_mutex_t ledger_mutex=PTHREAD_MUTEX_INITIALIZER;
static pid_t capture_pid;static uint64_t ledger_failures;
static void capture_identity(void){
 if(capture_pid==getpid())return;
 /* Called at worker attachment, before engine threads are started. */
 capture_pid=getpid();ledger_head=NULL;
 uint64_t seed[2]={now_ns(),((uint64_t)getpid()<<32)^clock()};
 int fd=open("/dev/urandom",O_RDONLY|O_CLOEXEC);if(fd>=0){ssize_t got=read(fd,seed,sizeof seed);(void)got;close(fd);}
 snprintf(capture_id,sizeof capture_id,"%016"PRIx64"%016"PRIx64,seed[0],seed[1]);
}
static void register_run(struct run_state*s){
 capture_identity();struct run_ledger*l=calloc(1,sizeof *l);
 if(!l){s->lost++;__atomic_add_fetch(&ledger_failures,1,__ATOMIC_RELAXED);return;}
 l->run=s->id;l->tid=(pid_t)syscall(SYS_gettid);s->ledger=l;
 pthread_mutex_lock(&ledger_mutex);l->next=ledger_head;ledger_head=l;pthread_mutex_unlock(&ledger_mutex);
}
static void write_worker_manifest(bool closed){
 if(!closed)flush_disk();
 const char*dir=getenv("JIPSTATS_EVIDENCE_DIR");if(!dir||!*dir)return;
 char path[PATH_MAX],temp[PATH_MAX];
 if(snprintf(path,sizeof path,"%s/worker-%ld.manifest.json",dir,(long)getpid())>=(int)sizeof path)return;
 if(snprintf(temp,sizeof temp,"%s.tmp",path)>=(int)sizeof temp)return;
 int fd=open(temp,O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC|O_NOFOLLOW,0600);
 if(fd<0){__atomic_add_fetch(&ledger_failures,1,__ATOMIC_RELAXED);return;}
 FILE*f=fdopen(fd,"w");if(!f){close(fd);return;}
 fprintf(f,"{\"schema\":2,\"producer\":\"jipstats-1.6.13-dev\",\"capture\":\"%s\",\"pid\":%ld,\"scope\":\"one_worker_process\",\"process_closed\":%s,\"ledger_tail_on_each_record\":true,\"gzip_member_at_run_seal\":true,\"runs\":[",capture_id,(long)getpid(),closed?"true":"false");
 pthread_mutex_lock(&ledger_mutex);bool comma=false;
 for(struct run_ledger*l=ledger_head;l;l=l->next){
  fprintf(f,"%s{\"key\":\"%s:%ld:%ld:%"PRIu64"\",\"events\":%"PRIu64",\"sealed\":%s,\"tip\":\"%s\"}",comma?",":"",capture_id,(long)getpid(),(long)l->tid,l->run,l->events,l->sealed?"true":"false",l->tip);comma=true;
 }
 pthread_mutex_unlock(&ledger_mutex);
 fprintf(f,"],\"dropped_records\":%"PRIu64",\"ledger_failures\":%"PRIu64",\"unbound_hook_calls\":%"PRIu64",\"ambiguous_seq_bindings\":%"PRIu64",\"unbound_hook_kinds\":{",__atomic_load_n(&dropped_records,__ATOMIC_RELAXED),__atomic_load_n(&ledger_failures,__ATOMIC_RELAXED),__atomic_load_n(&unbound_hook_calls,__ATOMIC_RELAXED),__atomic_load_n(&ambiguous_seq_bindings,__ATOMIC_RELAXED));
 comma=false;for(unsigned k=0;k<=H_LENS;k++){uint64_t calls=__atomic_load_n(&unbound_hook_kinds[k],__ATOMIC_RELAXED);if(calls){fprintf(f,"%s\"%s\":%"PRIu64,comma?",":"",kind_names[k],calls);comma=true;}}
 fprintf(f,"},\"authenticated\":false}\n");
 bool ok=!ferror(f);if(fclose(f))ok=false;if(ok){if(rename(temp,path)){__atomic_add_fetch(&ledger_failures,1,__ATOMIC_RELAXED);if(disk_only)disk_failure();}}else unlink(temp);
}
static void emit(struct run_state*s,const char*phase,bool terminal,const char*fmt,...) __attribute__((format(printf,4,5)));
static void emit(struct run_state*s,const char*phase,bool terminal,const char*fmt,...){
 int saved=errno;uint64_t emit_start=now_ns();if(reporting){errno=saved;return;}
 if(!terminal && s && s->records>=record_limit){s->lost++;__atomic_add_fetch(&dropped_records,1,__ATOMIC_RELAXED);errno=saved;return;}
 char fields[2600],line[MAX_RECORD];va_list args;va_start(args,fmt);int f=vsnprintf(fields,sizeof fields,fmt,args);va_end(args);
 if(f<0||(size_t)f>=sizeof fields){if(s)s->lost++;__atomic_add_fetch(&dropped_records,1,__ATOMIC_RELAXED);errno=saved;return;}
 uint64_t nr=s?++s->records:0;
 if(s&&!strcmp(phase,"final"))s->final_event=nr;
 int n=snprintf(line,sizeof line,"IC3_STATS phase=%s origin=preload backend=events run=%" PRIu64 " event=%" PRIu64 " pid=%ld tid=%ld schema=%u capture=%s ctx_rev=%"PRIu64" model_epoch=%"PRIu64" op_id=%"PRIu64" %s",
   phase,s?s->id:0,nr,(long)getpid(),(long)syscall(SYS_gettid),frame_chunks_enabled?3:2,capture_id,s?s->context_revision:0,s?s->model_epoch:0,s?s->current_operation:0,fields);
 if(n<0||(size_t)n+74>sizeof line){if(s)s->lost++;__atomic_add_fetch(&dropped_records,1,__ATOMIC_RELAXED);errno=saved;return;}
 if(s){char next[65];chain_hash(s->chain,line,(size_t)n,next);memcpy(s->chain,next,65);n+=snprintf(line+n,sizeof line-(size_t)n," chain=%s",next);}

 __atomic_add_fetch(&generated_records,1,__ATOMIC_RELAXED);
 line[n]='\n';disk_record(line,(size_t)n+1);line[n]=0;
 /* Preserve the captured tail even if a budget stops the native run before a
  * final/seal. The ledger owns these bytes beyond the live run-state lifetime. */
 if(s&&s->ledger){pthread_mutex_lock(&ledger_mutex);s->ledger->events=s->records;memcpy(s->ledger->tip,s->chain,65);pthread_mutex_unlock(&ledger_mutex);}

 if(s&&!disk_only){
  if(!s->callback_entry)resolve_callback(s);
  if(s->callback_entry){
   void(*report)(void*,const char*,unsigned,bool)=NULL;memcpy(&report,&s->callback_entry,sizeof report);
   reporting=true;report((void*)s->callback,line,0,true);reporting=false;
   __atomic_add_fetch(&forwarded_records,1,__ATOMIC_RELAXED);
  }else{s->callback_failures++;__atomic_add_fetch(&callback_failures,1,__ATOMIC_RELAXED);}
 }
 if(s)s->emit_wall_ns+=now_ns()-emit_start;
 errno=saved;
}
static struct run_state *lookup_run(uintptr_t jip,uintptr_t seq){
 for(unsigned i=0;i<MAX_RUNS;i++)if(runs[i].live&&!runs[i].run_unwound&&runs[i].jip==jip&&runs[i].seq==seq)return &runs[i];
 return NULL;
}
static struct run_state *get_run(uintptr_t jip,uintptr_t seq){
 if(!jip||!seq)return NULL;
 struct run_state*existing=lookup_run(jip,seq);if(existing)return existing;
 for(unsigned i=0;i<MAX_RUNS;i++)if(!runs[i].live){
  struct run_state*s=&runs[i];memset(s,0,sizeof *s);s->live=true;s->jip=jip;s->seq=seq;
  s->id=__atomic_add_fetch(&next_id,1,__ATOMIC_RELAXED);s->last_depth=UNAVAILABLE;s->max_obligations=UNAVAILABLE;
  __atomic_add_fetch(&instances,1,__ATOMIC_RELAXED);resolve_callback(s);register_run(s);s->current_kind=-1;return s;
 }
 __atomic_add_fetch(&dropped_records,1,__ATOMIC_RELAXED);return NULL;
}
static int depth(struct run_state*s){int k=read_i32(s,s->seq,P.k_offset);if(k>=0&&k<100000000)s->last_depth=k+2;return s->last_depth;}
static int obligations(struct run_state*s){int v=read_i32(s,s->seq,P.obligations_offset);if(v>=0&&v>s->max_obligations)s->max_obligations=v;return v;}
static int cube_size(struct run_state*s,uintptr_t cube){
 if(!cube)return UNAVAILABLE;
 int n=read_i32(s,cube,(int)P.cube_size);return n>=0&&n<=10000000?n:UNAVAILABLE;
}
#include "details.h"
static void semantic_abort_seal(struct run_state*s);
#include "activations.h"
#include "semantics.h"
static void retire_abandoned(struct run_state*s,uint64_t generation){
 if(s->live&&s->id==generation&&s->run_unwound&&!s->activation_live){
  if(s->final_event){observer_anomaly(s,generation,"run_aborted_after_native_final");semantic_seal(s);}
  else semantic_abort_seal(s);
  s->live=false;if(current==s)current=NULL;destroy_details(s);
 }
}
static void retire_abandoned_runs(void){
 for(unsigned i=0;i<MAX_RUNS;i++)retire_abandoned(&runs[i],runs[i].id);
}
/* A native final/validation return is not the last ICSeq operation. Jasper
 * can still remove/subsume clauses before the next initialization. Retain the
 * registered context for that tail; seal without reading native memory only
 * when initialization replaces its identity or the worker exits normally. */
static void completion_tail_begin(struct run_state*s);
static void begin_ready_completion_tails(void){
 for(unsigned i=0;i<MAX_RUNS;i++)completion_tail_begin(&runs[i]);
}
static bool retire_completed_runs(uintptr_t jip,uintptr_t seq,bool all){
 bool unambiguous=true;
 for(unsigned i=0;i<MAX_RUNS;i++){
  struct run_state*s=&runs[i];
  if(s->live&&!s->run_unwound&&s->await_validation&&s->final_event&&!s->activation_live&&(all||s->jip==jip||s->seq==seq)){
   s->validation_missing=true;s->await_validation=false;s->pending_seal=true;
   emit(s,"native_validation_missing",false,"native_final_event=%"PRIu64" expected_native_validation=1 validation_observed=0 capture_complete=0 boundary=%s",s->final_event,all?"worker_exit":"native_init_rebind");
   completion_tail_begin(s);
  }
  if(!all&&s->live&&s->completion_tail&&s->activation_live&&(s->jip==jip||s->seq==seq)){
   observer_anomaly(s,s->id,"native_init_rebind_with_live_completion_tail");unambiguous=false;
  }
  if(s->live&&!s->run_unwound&&s->pending_seal&&s->completion_tail&&!s->activation_live&&!s->await_validation&&(all||s->jip==jip||s->seq==seq)){
   semantic_seal(s);s->live=false;if(current==s)current=NULL;destroy_details(s);
  }
 }
 return unambiguous;
}
static void completion_tail_begin(struct run_state*s){
 if(s->live&&!s->run_unwound&&s->pending_seal&&!s->activation_live&&!s->await_validation&&!s->completion_tail){
  s->completion_tail=true;
  if(s->final_validation_aborted)emit(s,"native_validation_abort",false,"native_final_event=%"PRIu64" abort_event=%"PRIu64" reason=native_handler_unwind native_return_observed=0 native_validation_end_observed=0 validation_pass_observed=0 validation_outcome=aborted_inconclusive",s->final_event,s->validation_abort_event);
  emit(s,"native_tail_begin",false,"native_final_event=%"PRIu64" native_verdict_already_observed=1 native_validation_expected=%u native_validation_observed=%u native_validation_aborted=%u native_validation_abort_event=%"PRIu64" proof_frontier=0 tail_binding=registered_unique_seq native_lifetime_certified=0 context_retained_until=native_init_rebind_or_worker_exit",s->final_event,s->final_validation_expected,s->final_validation_observed,s->final_validation_aborted,s->validation_abort_event);
  /* Checkpoint authoritative result/tail boundary, with sealed=false. A
   * killed worker still has an incomplete tail, never a complete archive. */
  write_worker_manifest(false);
 }
}
#include "parity.h"
static uintptr_t argument(GumInvocationContext*ctx,int n){return n<0?0:(uintptr_t)gum_invocation_context_get_nth_argument(ctx,(guint)n);}

static struct run_state *find_seq(uintptr_t seq){
 struct run_state*match=NULL;
 for(unsigned i=0;i<MAX_RUNS;i++)if(runs[i].live&&!runs[i].run_unwound&&runs[i].seq==seq){
  if(match){__atomic_add_fetch(&ambiguous_seq_bindings,1,__ATOMIC_RELAXED);return NULL;}
  match=&runs[i];
 }
 return match;
}
/* These exact native callers pass ICSeq::pending_invariants in RDI and keep
 * the actual ICSeq in RBP. Resolve only a unique registered generation, never
 * a cached vector range or the most recently observed instance. The complete
 * worker hash and the installed callee guard qualify the code identity. */
static bool pending_front_callsite(struct hook*h,uintptr_t caller){
 if(h->kind!=H_FRONTREMOVE||h->fixed_flags!=0)return false;
 if(!strcmp(P.hash,"b5006df1ff1ab23d9effd5eec464b1962a0905da1880aaa8fae574a4a9a81604"))return h->rva==0x17048e0&&caller==bias+0x170121b;
 if(!strcmp(P.hash,"e8cbfa93df42061662aaa530125f47d9255ff29b160aa3559d65c706bb24ce1d"))return h->rva==0xca6300&&caller==bias+0xca2bf2;
 return false;
}
static struct run_state*pending_front_owner(uintptr_t front,uintptr_t seq){
 if(!seq||seq>UINTPTR_MAX-152||front!=seq+152)return NULL;
 return find_seq(seq);
}
static bool extended_kind(enum hook_kind k){return k>=H_GETSTATS&&k<=H_SATAFTER;}
static void unbound_hook(struct hook*h,uintptr_t jip,uintptr_t seq){
 __atomic_add_fetch(&unbound_hook_calls,1,__ATOMIC_RELAXED);
 if(__atomic_add_fetch(&unbound_hook_kinds[h->kind],1,__ATOMIC_RELAXED)==1)diagnostic("native_hook_unbound hook=%s jip_arg=%"PRIxPTR" seq_arg=%"PRIxPTR" coverage_complete=0",kind_names[h->kind],jip,seq);
}
/* Failed attribution is evidence, never a guessed owner. Bound the diagnostic
 * sample; the manifest still counts every lost call. No native dereferences. */
static void diagnose_unbound_front(GumInvocationContext*ctx,struct hook*h){
 if(h->kind!=H_FRONTREMOVE||__atomic_load_n(&unbound_hook_kinds[H_FRONTREMOVE],__ATOMIC_RELAXED)>8)return;
 uintptr_t front=argument(ctx,0);
 diagnostic("native_frontremove_unbound native_entry=%"PRIxPTR" caller=%"PRIxPTR" front_arg=%"PRIxPTR" cube_arg=%"PRIxPTR" removed_vector_arg=%"PRIxPTR" gum_depth=%u current_run=%"PRIu64" attribution_inferred=0",h->rva,(uintptr_t)gum_invocation_context_get_return_address(ctx)-bias,front,argument(ctx,1),argument(ctx,2),gum_invocation_context_get_depth(ctx),current?current->id:0);
 for(unsigned i=0;i<MAX_RUNS;i++){
  struct run_state*s=&runs[i];if(!s->id)continue;
  diagnostic("native_frontremove_registered_context run=%"PRIu64" live=%u unwound=%u tail=%u seq=%"PRIxPTR" jip=%"PRIxPTR" exact_invariant_set=%u exact_pending_set=%u active_scopes=%"PRIu64" native_lifetime_certified=0",s->id,s->live,s->run_unwound,s->completion_tail,s->seq,s->jip,front==s->seq+120,front==s->seq+152,s->activation_live);
 }
}
static bool tail_hook_allowed(struct run_state*s,struct hook*h){
 if(!s->completion_tail||h->kind==H_SUBSUMPTION||h->kind==H_FRONTREMOVE)return true;
 s->observer_errors++;
 emit(s,"tail_scope_violation",false,"hook=%s search_resumption_not_classified_as_cleanup=1 capture_complete=0",kind_names[h->kind]);
 return false;
}
static void enter_hook(GumInvocationContext*ctx,gpointer user){
 int saved=errno;struct hook*h=user;
 struct invocation*v=gum_invocation_context_get_listener_invocation_data(ctx,sizeof *v);memset(v,0,sizeof *v);
 if(reporting){errno=saved;return;}
 if(observer_listener_alias(ctx,h)){errno=saved;return;}
 /* This validation-only listener intentionally excludes other callers of the
  * shared isInitial function; the profiled call-site filter predates binding
  * coverage accounting. A missing context at this site still counts loss. */
 if(h->kind==H_ISINITIAL&&(uintptr_t)gum_invocation_context_get_return_address(ctx)!=bias+(parity_target()?0x16dea1a:0xc8124a)){errno=saved;return;}
 observer_reconcile(gum_invocation_context_get_depth(ctx),false);
 retire_abandoned_runs();
 begin_ready_completion_tails();
 if(h->kind==H_INIT&&!retire_completed_runs(argument(ctx,h->jip_arg),argument(ctx,h->seq_arg),false)){
  unbound_hook(h,argument(ctx,h->jip_arg),argument(ctx,h->seq_arg));errno=saved;return;
 }
 v->previous=current;
 if(h->kind==H_FRONTREMOVE&&pending_front_callsite(h,(uintptr_t)gum_invocation_context_get_return_address(ctx))){
  v->state=pending_front_owner(argument(ctx,0),ctx->cpu_context->rbp);
  v->pending_front_binding=v->state!=NULL;
 }else if(h->kind==H_SAT||h->kind==H_QUEUEPUSH||h->kind==H_PODISPOSE||h->kind==H_GETCEX||h->kind==H_FRONTREMOVE){
  v->state=current&&current->live&&!current->run_unwound?current:NULL;
 }else if(h->kind==H_VALIDATION){v->state=lookup_run(argument(ctx,h->jip_arg),argument(ctx,h->seq_arg));}
 else if(h->kind==H_PREDECESSOR){v->state=find_seq(argument(ctx,1));}
 else if(h->kind==H_ISINITIAL){v->state=current&&current->live&&!current->run_unwound&&current->validation_active?current:NULL;}
 else if(extended_kind(h->kind))v->state=find_seq(argument(ctx,h->seq_arg));
 else v->state=h->kind==H_INIT?get_run(argument(ctx,h->jip_arg),argument(ctx,h->seq_arg)):lookup_run(argument(ctx,h->jip_arg),argument(ctx,h->seq_arg));
 if(!v->state){
  unbound_hook(h,argument(ctx,h->jip_arg),argument(ctx,h->seq_arg));
  diagnose_unbound_front(ctx,h);
  errno=saved;return;
 }struct run_state*s=v->state;
 if(!tail_hook_allowed(s,h)){errno=saved;return;}
 current=s;v->enabled=true;struct detailed_state*d=ds(s);
 if(!d){v->enabled=false;current=v->previous;errno=saved;return;}
 v->cube=argument(ctx,h->cube_arg);v->frame=h->frame_arg>=0?(int)(int32_t)argument(ctx,h->frame_arg):UNAVAILABLE;
 v->flags=h->flags_arg>=0?(int)(uint32_t)argument(ctx,h->flags_arg):h->fixed_flags;
 v->before_size=cube_size(s,v->cube);v->operation=++d->operation;
 s->parity_enabled=parity_target();
 semantic_contract(s);
 if(!observer_enter(ctx,h,v)){v->enabled=false;current=v->previous;errno=saved;return;}
 semantic_scope_enter(s,h,v);
 char native[768];native_fields(s,native);
 switch(h->kind){
 case H_PREDECESSOR:
  v->pointers[0]=argument(ctx,3);v->pointers[1]=argument(ctx,4);v->frame=(int)(int32_t)argument(ctx,2);break;
 case H_VALIDATION:
  v->pointers[5]=argument(ctx,h->jip_arg);
  model_context_observe(s,"validation_enter",v->pointers[5]);
  parity_validation_enter(s,argument(ctx,3));break;
 case H_ISINITIAL:
  v->enabled=s->validation_active && (uintptr_t)gum_invocation_context_get_return_address(ctx)==bias+(parity_target()?0x16dea1a:0xc8124a);break;
 case H_INIT:model_epoch_begin(s);parity_configuration(s);emit(s,"init",false,"depth=%d details_abi=%u",depth(s),P.details);break;
 case H_FRAME:s->frame_calls++;emit(s,"frame_begin",false,"depth=%d observed_frame_calls=%"PRIu64" %s",depth(s),s->frame_calls,native);break;
 case H_RELATIVE:
  v->previous_relative=s->current_relative;
  /* Record every distinct native invocation, including nested wrappers.
   * Equal arguments alone do not establish equivalent query semantics. */
  s->rel_depth++;
  v->id=++s->relative_calls;s->current_relative=v->id;
  d->relative_frame=v->frame;d->relative_flags=v->flags;d->relative_cube=v->cube;
  __atomic_add_fetch(&active_queries,1,__ATOMIC_RELAXED);
  emit(s,"relative_begin",false,"query=%"PRIu64" parent_query=%"PRIu64" operation=%"PRIu64" generalization=%"PRIu64" frame=%d depth=%d flags=%u cube_lits=%d nested_hooks_can_share_solver_work=1 %s",v->id,v->previous_relative,v->operation,d->current_generalize,v->frame,depth(s),(unsigned)v->flags,v->before_size,native);
  sample_cube(s,v->cube,v->id,"input");semantic_query_begin(s,h,v);break;
 case H_SAT:{
  v->id=++s->solver_calls;v->previous_relative=s->current_relative;
  int assumptions=h->frame_arg>=0?v->frame:v->before_size;uintptr_t data=0;
  if(h->cube_arg>=0&&v->cube)read_u64(v->cube+P.cube_data,&data);
  else data=argument(ctx,1);
  uint64_t payload=include_cubes?capture_vector_data(s,data,assumptions,"sat_literal_raw"):0;
  __atomic_add_fetch(&active_queries,1,__ATOMIC_RELAXED);
  emit(s,"sat_begin",false,"call=%"PRIu64" relative_query=%"PRIu64" frame=%d flags=%u depth=%d cube_lits=%d assumptions=%d assumptions_id=%"PRIu64" budget=%d %s",v->id,v->previous_relative,d->relative_frame,(unsigned)d->relative_flags,depth(s),cube_size(s,d->relative_cube),assumptions,payload,v->flags,native);break;}
 case H_PUSH:
  if(h->frame_arg<0)v->frame=h->frame_arg==-2?1:0;
  if(d->push_depth++){v->suppressed=true;break;}
  s->push_calls++;emit(s,"push_begin",false,"depth=%d call=%"PRIu64" early=%d mode=%d %s",depth(s),s->push_calls,v->frame,v->flags,native);break;
 case H_BLOCK:
  v->previous_heap=d->heap;if(full_abi())d->heap=argument(ctx,4);
  s->block_calls++;emit(s,full_abi()?"block_cube_begin":"block_begin",false,"depth=%d operation=%"PRIu64" cube_lits=%d %s",depth(s),v->operation,v->before_size,native);
  sample_cube(s,v->cube,0,"block_input");queue_snapshot(s,"block_enter",v->operation);break;
 case H_OBLIGATION:{
  v->previous_heap=d->heap;if(full_abi())d->heap=argument(ctx,1);
  s->obligation_process_calls++;
  if(full_abi()){
   bool use_long=read_i32(s,d->heap,116)>0&&read_i32(s,d->heap,24)>read_i32(s,d->heap,20);
   v->heap=d->heap+(use_long?112:48);uintptr_t po=queue_top(s,v->heap);v->pointers[0]=po;v->po_id=define_po(s,po);
  }
  emit(s,"obligation_process_begin",false,"operation=%"PRIu64" obligation_id=%"PRIu64" depth=%d process_calls=%"PRIu64" %s",v->operation,v->po_id,depth(s),s->obligation_process_calls,native);
  queue_snapshot(s,"process_enter",v->operation);break;}
 case H_GENERALIZE:
  v->pointers[5]=full_cube(s,v->cube);
  v->previous_generalize=d->current_generalize;v->id=++d->gen_id;d->current_generalize=v->id;
  s->generalize_calls++;emit(s,"generalize_begin",false,"generalization=%"PRIu64" frame=%d depth=%d cube_lits=%d call=%"PRIu64" %s",v->id,v->frame,depth(s),v->before_size,s->generalize_calls,native);
  sample_cube(s,v->cube,s->current_relative,"generalize_input");break;
 case H_RUN:emit(s,"run_begin",false,"depth=%d %s",depth(s),native);break;
 case H_STATS:
  v->result=read_i32(s,argument(ctx,2),0);d->have_final=false;
  emit(s,"final_begin",false,"result_raw=%d depth=%d %s",v->result,depth(s),native);break;
 case H_GETSTATS:
  v->frame=(int)argument(ctx,2);for(int i=0;i<4;i++)v->pointers[i]=argument(ctx,i+3);break;
 case H_TOTALCUBES:v->flags=(int)argument(ctx,1);break;
 case H_ADDCUBE:
  d->add_depth++;v->id=full_cube(s,v->cube);
  emit(s,"clause_insert_begin",false,"operation=%"PRIu64" cube_id=%"PRIu64" frame=%d pushed=%u %s",v->operation,v->id,v->frame,(unsigned)v->flags&1,native);break;
 case H_SUBSUMPTION:v->id=full_cube(s,v->cube);break;
 case H_FRONTREMOVE:
  v->pointers[0]=argument(ctx,0);v->pointers[1]=argument(ctx,2);v->id=full_cube(s,argument(ctx,1));break;
 case H_QUEUEPUSH:{
  v->heap=argument(ctx,0);uintptr_t po=0;read_u64(argument(ctx,1),&po);v->pointers[0]=po;
  v->po_id=define_po(s,po);v->before_size=read_i32(s,v->heap,4);
  emit(s,"obligation_enqueue_begin",false,"operation=%"PRIu64" obligation_id=%"PRIu64" queue_address=%"PRIxPTR" native_count=%d",v->operation,v->po_id,v->heap,v->before_size);break;}
 case H_PODISPOSE:{
  uintptr_t po=argument(ctx,0)+16;struct po_definition*item=g_hash_table_lookup(d->pos,(gpointer)po);
  if(item){emit(s,"obligation_destroy",false,"obligation_id=%"PRIu64" native_address=%"PRIxPTR,item->id,po);g_hash_table_remove(d->pos,(gpointer)po);}break;}
 case H_GETCEX:{
  v->po_id=define_po(s,argument(ctx,0));emit(s,"obligation_cex_chain",false,"head_id=%"PRIu64" scope=native_ICProofObl_getCex",v->po_id);break;}
 default:break;
 }
 observer_update(v);
 v->start=now_ns();v->cpu_start=clock_ns(CLOCK_THREAD_CPUTIME_ID);v->process_start=clock_ns(CLOCK_PROCESS_CPUTIME_ID);errno=saved;
}
static void leave_hook(GumInvocationContext*ctx,gpointer user){
 int saved=errno;struct hook*h=user;struct invocation*v=gum_invocation_context_get_listener_invocation_data(ctx,sizeof *v);
 if(reporting){errno=saved;return;}
 if(!v->activation_token){errno=saved;return;}
 observer_reconcile(gum_invocation_context_get_depth(ctx),true);
 if(!observer_matches(h,v)){errno=saved;return;}
 if(!v->enabled){observer_return(h,v);errno=saved;return;}
 struct run_state*s=v->state;struct detailed_state*d=s->detail;
 int result=(int)(int32_t)(uintptr_t)gum_invocation_context_get_return_value(ctx);
 uint64_t elapsed=now_ns()-v->start,cpu=clock_ns(CLOCK_THREAD_CPUTIME_ID)-v->cpu_start,pcpu=clock_ns(CLOCK_PROCESS_CPUTIME_ID)-v->process_start;
 char native[768];native_fields(s,native);
 switch(h->kind){
 case H_PREDECESSOR:
  if(full_abi()){
   uint64_t source=full_cube(s,v->pointers[0]),pred=full_cube(s,v->pointers[1]);
   emit(s,"predecessor_cubes",false,"frame=%d source_cube_id=%"PRIu64" predecessor_cube_id=%"PRIu64" complete=%u scope=engine_search_states_not_concrete_reachability",v->frame,source,pred,source!=0&&pred!=0);
  }
  parity_cti(s,v->frame,v->pointers[0],v->pointers[1]);break;
 case H_VALIDATION:
  parity_validation_leave(s);model_context_observe(s,"validation_leave",v->pointers[5]);break;
 case H_ISINITIAL:
  s->validation_base_count++;
  if(result&1){s->validation_failed=true;parity_record(s,"IC3_VALIDATION","phase=base result=fail reason=initial-state-intersection");}break;
 case H_RELATIVE:
  if(s->rel_depth)s->rel_depth--;
  if(!v->suppressed){
   const char*name;
   if(result==P.rel_true){s->relative_sat++;name="sat";}
   else if(result==P.rel_false){s->relative_unsat++;name="unsat";}
   else if(result==P.rel_unknown){s->relative_limit++;name="limit";}
   else{s->relative_other++;name="unknown_encoding";__atomic_add_fetch(&unknown_results,1,__ATOMIC_RELAXED);}
   __atomic_sub_fetch(&active_queries,1,__ATOMIC_RELAXED);
   native_fields(s,native);
   emit(s,"relative_end",false,"query=%"PRIu64" result=%s result_raw=%d wall_ns=%"PRIu64" thread_cpu_ns=%"PRIu64" process_cpu_ns=%"PRIu64" frame=%d cube_lits=%d %s",v->id,name,result,elapsed,cpu,pcpu,v->frame,cube_size(s,v->cube),native);
   sample_cube(s,v->cube,v->id,"output");semantic_query_end(s,v,result);s->current_relative=v->previous_relative;
   d->relative_frame=d->relative_flags=-1;d->relative_cube=0;
  }break;
 case H_SAT:{
  const char*name;
  if(result==P.sat_true){s->solver_sat++;name="sat";}
  else if(result==P.sat_false||result==P.sat_assume){s->solver_unsat++;name="unsat";}
  else{s->solver_limit++;name="limit_or_unknown";}
  __atomic_sub_fetch(&active_queries,1,__ATOMIC_RELAXED);
  emit(s,"sat_end",false,"call=%"PRIu64" relative_query=%"PRIu64" result=%s result_raw=%d wall_ns=%"PRIu64" thread_cpu_ns=%"PRIu64" process_cpu_ns=%"PRIu64" elapsed=%.9f frame=%d depth=%d cube_lits=%d %s",v->id,v->previous_relative,name,result,elapsed,cpu,pcpu,pcpu/1e9,d->relative_frame,depth(s),cube_size(s,d->relative_cube),native);break;}
 case H_PUSH:
  if(h->frame_arg<0)v->frame=h->frame_arg==-2?1:0;
  if(d->push_depth)d->push_depth--;
  if(!v->suppressed){emit(s,"push_end",false,"depth=%d fixpoint=%u early=%d mode=%d wall_ns=%"PRIu64" %s",depth(s),(unsigned)result&1,v->frame,v->flags,elapsed,native);frame_snapshot(s,"push_end",v->operation);}break;
 case H_BLOCK:
  emit(s,"block_end",false,"depth=%d operation=%"PRIu64" return_bool=%u cube_lits=%d wall_ns=%"PRIu64" %s",depth(s),v->operation,(unsigned)result&1,cube_size(s,v->cube),elapsed,native);
  queue_snapshot(s,"block_leave",v->operation);frame_snapshot(s,"block_leave",v->operation);d->heap=v->previous_heap;break;
 case H_OBLIGATION:
  emit(s,"obligation_process_end",false,"operation=%"PRIu64" obligation_id=%"PRIu64" depth=%d return_bool=%u wall_ns=%"PRIu64" %s",v->operation,v->po_id,depth(s),(unsigned)result&1,elapsed,native);
  queue_snapshot(s,"process_leave",v->operation);d->heap=v->previous_heap;break;
 case H_GENERALIZE:
  if((unsigned)result&1)s->successful_generalizations++;
  if(v->before_size>cube_size(s,v->cube))s->removed_generalization_literals+=(uint64_t)(v->before_size-cube_size(s,v->cube));
  native_fields(s,native);
  emit(s,"generalize_end",false,"generalization=%"PRIu64" frame=%d return_bool=%u before=%d after=%d wall_ns=%"PRIu64" %s",v->id,v->frame,(unsigned)result&1,v->before_size,cube_size(s,v->cube),elapsed,native);
  sample_cube(s,v->cube,s->current_relative,"generalize_output");
  emit(s,"generalization_relation",false,"generalization=%"PRIu64" parent_generalization=%"PRIu64" frame=%d before_cube_id=%"PRIu64" after_cube_id=%"PRIu64" improved=%u",v->id,v->previous_generalize,v->frame,(uint64_t)v->pointers[5],full_cube(s,v->cube),(unsigned)result&1);
  d->current_generalize=v->previous_generalize;break;
 case H_FRAME:emit(s,"frame_end",false,"depth=%d %s",depth(s),native);frame_snapshot(s,"frame_created",v->operation);break;
 case H_INIT:
  emit(s,"init_end",false,"depth=%d return_bool=%u %s",depth(s),(unsigned)result&1,native);model_record(s);if(full_abi()){sample_cube(s,s->seq+216,0,"active_properties");sample_cube(s,s->seq+248,0,"assumed_valid_properties");frame_snapshot(s,"initial",v->operation);}break;
 case H_RUN:emit(s,"run_end",false,"depth=%d wall_ns=%"PRIu64" %s",depth(s),elapsed,native);d->heap=0;break;
 case H_STATS:
  parity_aggregate_final(s);full_final(s,v->result);semantic_scope_leave(s,h,v);
  if(native_validation_target()&&v->result==P.valid){s->await_validation=true;s->final_validation_expected=true;}
  else{s->pending_seal=true;}break;
 case H_GETSTATS:
  d->fixpoint=v->frame;d->cubes_total=read_i32(s,v->pointers[0],0);d->cubes_fix=read_i32(s,v->pointers[1],0);d->flops=read_i32(s,v->pointers[2],0);d->coi=read_i32(s,v->pointers[3],0);
  d->have_final=true;d->stats_checks++;
  emit(s,"native_getstats",false,"fixpoint_frame=%d clauses=%d fixpoint_clauses=%d invariant_flops=%d coi_flops=%d source=original_getStats_output_references",d->fixpoint,d->cubes_total,d->cubes_fix,d->flops,d->coi);verify_native_final(s);break;
 case H_TOTALCUBES:{
  int64_t a=-1,b=-1;if(population(s,&a,&b)){d->total_checks++;bool same=a+(v->flags?b:0)==result;if(!same)d->total_mismatch++;
   emit(s,"native_population_check",false,"include_invars=%u original=%d observed=%"PRId64" match=%u",v->flags!=0,result,a+(v->flags?b:0),same);}
  break;}
 case H_ADDCUBE:
  if(d->add_depth)d->add_depth--;
  emit(s,"clause_insert_end",false,"operation=%"PRIu64" cube_id=%"PRIu64" frame=%d pushed=%u %s",v->operation,v->id,v->frame,(unsigned)v->flags&1,native);frame_snapshot(s,"native_addCube",v->operation);break;
 case H_SUBSUMPTION:
  emit(s,"subsumption_end",false,"operation=%"PRIu64" by_cube_id=%"PRIu64" frame=%d method=%d result_known=%u result_raw=%d %s",v->operation,v->id,v->frame,h->fixed_flags,h->fixed_flags!=0,h->fixed_flags?result:0,native);
  frame_snapshot(s,"native_subsumption",v->operation);break;
 case H_FRONTREMOVE:
  removed_relationships(s,v->pointers[1],v->pointers[0],v->id,v->operation,(unsigned)h->fixed_flags,result);break;
 case H_QUEUEPUSH:
  d->observed_enqueues++;
  emit(s,"obligation_enqueue_end",false,"operation=%"PRIu64" obligation_id=%"PRIu64" queue_address=%"PRIxPTR" before=%d after=%d",v->operation,v->po_id,v->heap,v->before_size,read_i32(s,v->heap,4));
  queue_snapshot(s,"enqueue",v->operation);break;
 default:break;
 }
 if(s->live)semantic_scope_leave(s,h,v);
 observer_return(h,v);
 retire_abandoned(s,v->run_generation);
 completion_tail_begin(s);
 errno=saved;
}
static uintptr_t reg_value(GumCpuContext*c,int r){
 switch(r){case 0:return c->rdi;case 1:return c->rsi;case 2:return c->rdx;case 3:return c->rcx;case 4:return c->r8;case 5:return c->r9;case 6:return c->rax;case 7:return c->rbx;case 8:return c->rbp;case 9:return c->rsp;case 10:return c->r12;case 11:return c->r13;case 12:return c->r14;case 13:return c->r15;default:return 0;}
}
static void probe_hook(GumInvocationContext*ctx,gpointer user){
 int parity_saved_errno=errno;struct hook*parity_hook=user;
 if(reporting){errno=parity_saved_errno;return;}
 observer_reconcile(gum_invocation_context_get_depth(ctx),false);
 if(parity_hook->kind==H_LENS){
  struct run_state*s=lookup_run(ctx->cpu_context->r13,ctx->cpu_context->rbp);
  if(!s)unbound_hook(parity_hook,ctx->cpu_context->r13,ctx->cpu_context->rbp);
  if(s&&!tail_hook_allowed(s,parity_hook)){errno=parity_saved_errno;return;}
  if(s&&parity_target()){s->parity_enabled=true;struct detailed_state*d=ds(s);if(d){uintptr_t old=d->heap;d->heap=ctx->cpu_context->rbx;parity_lens(s);d->heap=old;}}
  errno=parity_saved_errno;return;
 }
 if(parity_hook->kind==H_VALBASE||parity_hook->kind==H_VALSTEP||parity_hook->kind==H_VALPROPERTY){
  if(current&&current->live&&!current->run_unwound&&current->validation_active)parity_validation_stage(current,parity_hook->kind);
  errno=parity_saved_errno;return;
 }
 int saved=errno;if(reporting){errno=saved;return;}struct hook*h=user;
 if(h->kind==H_SATBEFORE||h->kind==H_SATAFTER){
  if(current&&current->live&&!current->run_unwound){
   if(!tail_hook_allowed(current,h)){errno=saved;return;}
   if(current->validation_active)parity_validation_solver(current,h,ctx->cpu_context,h->kind==H_SATBEFORE);
   else sat_call_probe(current,h,ctx->cpu_context,h->kind==H_SATBEFORE,observer_current_token(current));
  }
  errno=saved;return;
 }
 if(h->kind==H_QUEUEUNLINK){
  struct run_state*s=current;
  if(s&&s->live&&!s->run_unwound&&s->detail&&full_abi()){
   uintptr_t node=ctx->cpu_context->rdi;
   uintptr_t po=(uintptr_t)g_hash_table_lookup(s->detail->nodes,(gpointer)node);
   if(po){
    uint64_t identity=(uint64_t)po;
    emit(s,"obligation_dequeue",false,"obligation_id=%"PRIu64" list_node=%"PRIxPTR" source=native_std_list_unhook discharge=not_implied",identity,node);
    g_hash_table_remove(s->detail->nodes,(gpointer)node);s->detail->observed_dequeues++;
   }
  }
  errno=saved;return;
 }
 struct run_state*s=lookup_run(reg_value(ctx->cpu_context,h->jip_arg),reg_value(ctx->cpu_context,h->seq_arg));
 if(!s){unbound_hook(h,reg_value(ctx->cpu_context,h->jip_arg),reg_value(ctx->cpu_context,h->seq_arg));errno=saved;return;}
 if(!tail_hook_allowed(s,h)){errno=saved;return;}
 struct run_state*previous=current;current=s;struct detailed_state*d=ds(s);
 if(!d){current=previous;errno=saved;return;}
 semantic_contract(s);
 uintptr_t prior=d->heap;d->heap=reg_value(ctx->cpu_context,h->frame_arg)+(uintptr_t)h->fixed_flags;
 char native[768];native_fields(s,native);
 if(h->kind==H_TRACE){
  emit(s,"block_begin",false,"boundary=native_cexAttempt depth=%d %s",depth(s),native);
  frame_snapshot(s,"trace_attempt",0);queue_snapshot(s,"trace_attempt",0);
 }else{
  int early=read_i32(s,d->heap,36)<=0;
  emit(s,"block_sample",false,"boundary=after_native_closeSample depth=%d early_push=%d short_queue=%d long_queue=%d %s",depth(s),early,read_i32(s,d->heap,52),read_i32(s,d->heap,116),native);
  queue_snapshot(s,"sample",0);
 }
 d->heap=prior;current=previous;errno=saved;
}
struct identity{struct stat st;bool found;};
static bool mapped_identity(struct dl_phdr_info*i,const struct stat*st){
 FILE*f=fopen("/proc/self/maps","r");if(!f)return false;char line[PATH_MAX+160];bool match=false;
 while(fgets(line,sizeof line,f)){
  unsigned long a,b,off;unsigned maj,min;unsigned long long ino;char perm[5];
  if(sscanf(line,"%lx-%lx %4s %lx %x:%x %llu",&a,&b,perm,&off,&maj,&min,&ino)!=7)continue;
  if((ino_t)ino!=st->st_ino||makedev(maj,min)!=st->st_dev)continue;
  for(unsigned k=0;k<i->dlpi_phnum;k++){const ElfW(Phdr)*p=&i->dlpi_phdr[k];uintptr_t pc=i->dlpi_addr+p->p_vaddr;
   if(p->p_type==PT_LOAD&&(p->p_flags&PF_X)&&pc>=a&&pc<b){match=true;break;}}
  if(match)break;
 }fclose(f);return match;
}
static int locate(struct dl_phdr_info*i,size_t ignored,void*arg){
 (void)ignored;struct identity*id=arg;struct stat st;const char*name=(i->dlpi_name&&*i->dlpi_name)?i->dlpi_name:"/proc/self/exe";
 if((!stat(name,&st)&&st.st_dev==id->st.st_dev&&st.st_ino==id->st.st_ino)||mapped_identity(i,&id->st)){bias=i->dlpi_addr;id->found=true;return 1;}return 0;
}
static unsigned parse_hex(const char *hex,unsigned char*bytes){
 size_t len=strlen(hex);if(!len||len>64||len%2)return 0;
 for(size_t k=0;k<len/2;k++){char temp[3]={hex[k*2],hex[k*2+1],0};char*end;long v=strtol(temp,&end,16);if(*end||v<0||v>255)return 0;bytes[k]=(unsigned char)v;}return(unsigned)len/2;
}
static bool profile_read(const char*path){
 FILE*f=fopen(path,"r");if(!f)return false;char line[512];unsigned callback=0,slot=0;
 bool ok=fgets(line,sizeof line,f)&&!strcmp(line,"JIPSTATS_EVENTS 1\n");
 ok=ok&&fgets(line,sizeof line,f)&&sscanf(line,"sha256 %64s",P.hash)==1&&strlen(P.hash)==64;
 ok=ok&&fgets(line,sizeof line,f)&&sscanf(line,"callback %u %u",&callback,&slot)==2&&callback<1048576&&slot<=256;
 P.callback=callback;P.report_slot=slot;
 ok=ok&&fgets(line,sizeof line,f)&&sscanf(line,"fields %d %d %d %d %d %d",&P.k_offset,&P.obligations_offset,&P.pre_bad_offset,&P.pre_other_offset,&P.generalize_offset,&P.calls_offset)==6;
 ok=ok&&fgets(line,sizeof line,f)&&sscanf(line,"cube %u %u %u",&P.cube_data,&P.cube_size,&P.cube_item)==3&&P.cube_item==4&&P.cube_data<128&&P.cube_size<128;
 ok=ok&&fgets(line,sizeof line,f)&&sscanf(line,"relative_results %d %d %d",&P.rel_true,&P.rel_false,&P.rel_unknown)==3;
 ok=ok&&fgets(line,sizeof line,f)&&sscanf(line,"solver_results %d %d %d",&P.sat_true,&P.sat_false,&P.sat_assume)==3;
 ok=ok&&fgets(line,sizeof line,f)&&sscanf(line,"proof_results %d %d",&P.valid,&P.cex)==2;
 while(ok&&fgets(line,sizeof line,f)){
  if(line[0]=='#'||line[0]=='\n')continue;
  if(sscanf(line,"details %u",&P.details)==1){if(P.details!=1){ok=false;break;}continue;}
  if(P.nh>=MAX_HOOKS){ok=false;break;}struct hook*h=&P.hooks[P.nh];char kind[32],hex[65];unsigned long long rva;
  if(sscanf(line,"hook %31s %llx %d %d %d %d %d %d %64s",kind,&rva,&h->jip_arg,&h->seq_arg,&h->frame_arg,&h->flags_arg,&h->cube_arg,&h->fixed_flags,hex)!=9){ok=false;break;}
  unsigned k;for(k=0;k<sizeof(kind_names)/sizeof(kind_names[0]);k++)if(!strcmp(kind,kind_names[k]))break;
  if(k>=sizeof(kind_names)/sizeof(kind_names[0])||!(h->guard_len=parse_hex(hex,h->guard))){ok=false;break;}
  h->kind=(enum hook_kind)k;h->rva=(uintptr_t)rva;
  if(h->jip_arg < -1 || h->jip_arg>13 || h->seq_arg < -1 || h->seq_arg>13 || h->frame_arg < -2||h->frame_arg>13||h->flags_arg < -1||h->flags_arg>7||h->cube_arg < -1||h->cube_arg>7){ok=false;break;}
  for(unsigned x=0;x<P.nh;x++)if(P.hooks[x].rva==h->rva)ok=false;
  P.nh++;
 }
 fclose(f);
 if(P.k_offset< -1||P.k_offset>1048576||P.obligations_offset< -1||P.obligations_offset>1048576)ok=false;
 if(P.rel_true==P.rel_false||P.rel_true==P.rel_unknown||P.rel_false==P.rel_unknown||P.valid==P.cex||P.sat_true==P.sat_false||P.sat_true==P.sat_assume)ok=false;
 unsigned required=0;
 for(unsigned i=0;i<P.nh;i++){
  enum hook_kind kind=P.hooks[i].kind;
  if(kind==H_INIT||kind==H_RELATIVE||kind==H_SAT||kind==H_STATS)required|=1u<<kind;
  if(kind==H_SATBEFORE)required|=1u<<H_SAT;
 }
 return ok && required==((1u<<H_INIT)|(1u<<H_RELATIVE)|(1u<<H_SAT)|(1u<<H_STATS));
}
static void totals(void){
 if(gum_interceptor_get_native_unwind_fault()){
  while(observer_top){
   observer_anomaly(observer_top->call.state,observer_top->generation,"native_unwind_return_slot_coverage_lost");
   observer_abort_top("native_unwind_runtime_fault");
  }
 }
 retire_abandoned_runs();
 begin_ready_completion_tails();
 retire_completed_runs(0,0,true);
 diagnostic("summary observed_instances=%" PRIu64 " generated_records=%" PRIu64 " forwarded_records=%" PRIu64 " active_queries=%" PRIu64 " dropped_records=%" PRIu64 " read_failures=%" PRIu64 " unknown_results=%" PRIu64 " callback_failures=%" PRIu64 " unbound_hook_calls=%"PRIu64" ambiguous_seq_bindings=%"PRIu64,
  __atomic_load_n(&instances,__ATOMIC_RELAXED),__atomic_load_n(&generated_records,__ATOMIC_RELAXED),__atomic_load_n(&forwarded_records,__ATOMIC_RELAXED),__atomic_load_n(&active_queries,__ATOMIC_RELAXED),__atomic_load_n(&dropped_records,__ATOMIC_RELAXED),__atomic_load_n(&read_failures,__ATOMIC_RELAXED),__atomic_load_n(&unknown_results,__ATOMIC_RELAXED),__atomic_load_n(&callback_failures,__ATOMIC_RELAXED),__atomic_load_n(&unbound_hook_calls,__ATOMIC_RELAXED),__atomic_load_n(&ambiguous_seq_bindings,__ATOMIC_RELAXED));
 diagnostic("native_IC3_reports_redirected=%"PRIu64,__atomic_load_n(&native_reports_redirected,__ATOMIC_RELAXED));
 close_disk_sinks();write_worker_manifest(true);
}
static void *observer_provider_export(const char*module_name,const char*symbol_name){
 void*h=dlopen(module_name,RTLD_LAZY|RTLD_NOLOAD);
 void*result=h?dlsym(h,symbol_name):NULL;
 if(h)dlclose(h);
 return result;
}
__attribute__((constructor)) static void install_events(void){
 const char*profile=getenv("JIPSTATS_PROFILE"),*image=getenv("JIPSTATS_IMAGE");if(!profile||!image)return;
 if(!profile_read(profile)){diagnostic("profile_rejected; no hooks installed");return;}
 struct identity id={0};if(stat(image,&id.st))return;dl_iterate_phdr(locate,&id);if(!id.found)return;
 FILE*f=fopen(image,"rb");char hash[65];if(!f)return;bool ok=jipstats_sha256_file(f,hash)&&!strcmp(hash,P.hash);fclose(f);
 if(!ok){diagnostic("image_hash_mismatch; no hooks installed");return;}
 for(unsigned i=0;i<P.nh;i++){
  struct hook*h=&P.hooks[i];unsigned char actual[32];
  if(!executable(bias+h->rva)||!read_bytes(bias+h->rva,actual,h->guard_len)||memcmp(actual,h->guard,h->guard_len)){
   diagnostic("instruction_guard_mismatch hook=%s address=%lx bias=%lx errno=%d; no hooks installed",kind_names[h->kind],(unsigned long)h->rva,(unsigned long)bias,errno);return;
  }
 }
 compress_disk=getenv("JIPSTATS_COMPRESSION")&&!strcmp(getenv("JIPSTATS_COMPRESSION"),"gzip");
 disk_only=getenv("JIPSTATS_SINK")&&!strcmp(getenv("JIPSTATS_SINK"),"disk");
 if(disk_only&&(!getenv("JIPSTATS_EVIDENCE_DIR")||!*getenv("JIPSTATS_EVIDENCE_DIR")))disk_failure();
 capture_identity();
 const char*mode=getenv("JIPSTATS_CAPTURE_MODE");if(mode&&!strcmp(mode,"full"))full_snapshots=true;
 const char*encoding=getenv("JIPSTATS_FRAME_ENCODING");
 if(encoding&&(!strcmp(encoding,"tuple_chunks_v1")||!strcmp(encoding,"tuple_chunks_v2"))){frame_chunks_enabled=true;frame_inline_enabled=!strcmp(encoding,"tuple_chunks_v2");}
 else if(encoding&&strcmp(encoding,"members_v1")){fprintf(stderr,"[jipstats] unsupported_frame_encoding\n");return;}
 const char*limit=getenv("JIPSTATS_MAX_RECORDS");if(limit){char*end;unsigned long long n=strtoull(limit,&end,10);if(!*end&&n)record_limit=n;}
 const char*cubes=getenv("JIPSTATS_CUBES");if(cubes&&!strcmp(cubes,"0"))include_cubes=false;
 gum_init_embedded();interceptor=gum_interceptor_obtain();
 if(gum_interceptor_get_native_unwind_status()!=GUM_NATIVE_UNWIND_REQUIRED){
  diagnostic("native_unwind_install_incomplete status=%u; no observer hooks installed",gum_interceptor_get_native_unwind_status());return;
 }
 gum_interceptor_begin_transaction(interceptor);
 void*personalities[]={observer_provider_export("libstdc++.so.6","__gxx_personality_v0"),observer_provider_export("libgcc_s.so.1","__gcc_personality_v0")};
 observer_get_cfa=observer_provider_export("libgcc_s.so.1","_Unwind_GetCFA");
 if(!personalities[0]||!personalities[1]||!observer_get_cfa){diagnostic("unwind_runtime_missing; no hooks installed");gum_interceptor_end_transaction(interceptor);return;}
 observer_personality_listener=gum_make_call_listener(observer_personality_enter,observer_personality_leave,NULL,NULL);
 for(unsigned i=0;i<2;i++)if(gum_interceptor_attach(interceptor,personalities[i],observer_personality_listener,NULL)!=GUM_ATTACH_OK)ok=false;
 if(!ok){diagnostic("unwind_observer_attach_failed; no hooks installed");gum_interceptor_detach(interceptor,observer_personality_listener);gum_interceptor_end_transaction(interceptor);return;}
 const char*jump_names[]={"longjmp","_longjmp","siglongjmp","__longjmp_chk"};
 void*jump_entries[4]={0};
 observer_jump_listener=gum_make_probe_listener(observer_jump_enter,NULL,NULL);
 for(unsigned i=0;i<4;i++){
  void*fn=observer_provider_export("libc.so.6",jump_names[i]);if(!fn){ok=false;continue;}
  unsigned j;for(j=0;j<i&&jump_entries[j]!=fn;j++);if(j!=i)continue;
  jump_entries[i]=fn;
  if(gum_interceptor_attach(interceptor,fn,observer_jump_listener,NULL)!=GUM_ATTACH_OK){diagnostic("nonlocal_exit_observer_attach_failed");ok=false;}
 }
 for(unsigned i=0;i<P.nh;i++){
  struct hook*h=&P.hooks[i];h->listener=(h->kind==H_TRACE||h->kind==H_SAMPLE||h->kind==H_QUEUEUNLINK||h->kind==H_SATBEFORE||h->kind==H_SATAFTER||h->kind==H_VALBASE||h->kind==H_VALSTEP||h->kind==H_VALPROPERTY||h->kind==H_LENS)?gum_make_probe_listener(probe_hook,h,NULL):gum_make_call_listener(enter_hook,leave_hook,h,NULL);
  GumAttachReturn r=gum_interceptor_attach(interceptor,(void*)(bias+h->rva),h->listener,NULL);
  if(r!=GUM_ATTACH_OK){diagnostic("attach_failed hook=%s address=%lx rc=%d",kind_names[h->kind],(unsigned long)h->rva,r);ok=false;}
 }
 if(!ok){for(unsigned i=0;i<P.nh;i++)gum_interceptor_detach(interceptor,P.hooks[i].listener);gum_interceptor_detach(interceptor,observer_personality_listener);gum_interceptor_detach(interceptor,observer_jump_listener);}
 gum_interceptor_end_transaction(interceptor);
 if(!ok){diagnostic("transaction_rolled_back; no hooks installed");return;}
 diagnostic("attached sha256=%s hooks=%u producer_strings_required=0 debug_selector_modified=0",hash,P.nh);
 atexit(totals);
}
