/* Independent native-layout snapshot oracle. Not a Jasper proof. */
#ifndef FRAME_PRODUCER_FILE
#define FRAME_PRODUCER_FILE "../src/events.c"
#endif
#include FRAME_PRODUCER_FILE
#include <assert.h>
struct fixture_cube {uintptr_t data;int count,padding;uint32_t packed;};
struct fixture_frontier {uintptr_t begin,end,capacity,unused;};
#ifndef FIXTURE_CUBES
#define FIXTURE_CUBES 1024
#endif
#ifndef FIXTURE_MEMBERS
#define FIXTURE_MEMBERS FIXTURE_CUBES
#endif
static struct fixture_cube cubes[FIXTURE_CUBES];
static uint32_t literals[FIXTURE_CUBES];
static uintptr_t items[FIXTURE_MEMBERS],duplicates[67],invariants[65];
static unsigned char seq[352];
static struct fixture_frontier fronts[3];
static FILE*oracle;
#ifdef FRAME_PRODUCER_LEGACY_164
static uint64_t fixture_epoch;
static uint64_t fixture_get_epoch(struct run_state*s){(void)s;return fixture_epoch;}
static void fixture_epoch_begin(struct run_state*s){fixture_epoch++;s->detail->model_emitted=true;}
#else
static uint64_t fixture_get_epoch(struct run_state*s){return s->model_epoch;}
static void fixture_epoch_begin(struct run_state*s){model_epoch_begin(s);s->detail->model_emitted=true;}
#endif
static void oracle_write(const void*data,size_t size){assert(fwrite(data,1,size,oracle)==size);}
static void snapshot(struct run_state*s){
 uint64_t epoch=fixture_get_epoch(s),snap=s->detail->snapshot+1;uint32_t n=4;
 oracle_write(&epoch,8);oracle_write(&snap,8);oracle_write(&n,4);
 for(int f=0;f<4;f++){
  int32_t frame=f==3?-1:f;struct fixture_frontier*fr=f==3?(void*)(seq+120):fronts+f;
  uint32_t count=(fr->end-fr->begin)/8;oracle_write(&frame,4);oracle_write(&count,4);
  uintptr_t*members=(void*)fr->begin;
  for(uint32_t k=0;k<count;k++){
   struct fixture_cube*c=(void*)members[k];uint32_t raw=*(uint32_t*)c->data;
   oracle_write(&raw,4);oracle_write(&c->packed,4);
  }
 }
 emit(s,"frame_end",false,"depth=3 native_available=0");
 frame_snapshot(s,"fixture",0);
}
int main(int argc,char**argv){
 gum_init_embedded();
 assert(argc==4);disk_only=true;compress_disk=true;full_snapshots=true;
#ifdef FRAME_CHUNK_CACHE
 frame_chunks_enabled=!strcmp(argv[1],"compact");frame_inline_enabled=frame_chunks_enabled;
#else
 assert(!strcmp(argv[1],"legacy"));
#endif
 capture_identity();
 P.details=1;P.cube_data=0;P.cube_size=8;
 oracle=fopen(argv[3],"wb");assert(oracle);
 for(int i=0;i<FIXTURE_CUBES;i++){
  literals[i]=((uint32_t)i<<3)|2; /* Composite IDs avoid invented signal maps. */
  cubes[i]=(struct fixture_cube){(uintptr_t)&literals[i],1,0,(uint32_t)(i%4)|((i%2)?0x80000000U:0)};
 }
 for(unsigned i=0;i<FIXTURE_MEMBERS;i++){
  unsigned index=i%FIXTURE_CUBES;
  if(FIXTURE_MEMBERS>FIXTURE_CUBES){
   /* Each 64-member chunk has a unique pair, while the live cube dictionary
    * stays small. A single snapshot crosses the bounded chunk-cache limit. */
   unsigned chunk=i/64;
   if(i%64==0)index=chunk%FIXTURE_CUBES;
   else if(i%64==1)index=(chunk/FIXTURE_CUBES)%FIXTURE_CUBES;
  }
  items[i]=(uintptr_t)&cubes[index];
 }
 for(int i=0;i<67;i++)duplicates[i]=(uintptr_t)&cubes[i%7];
 for(int i=0;i<65;i++)invariants[i]=(uintptr_t)&cubes[900+i];
 fronts[0]=(struct fixture_frontier){(uintptr_t)items,(uintptr_t)(items+FIXTURE_MEMBERS),(uintptr_t)(items+FIXTURE_MEMBERS),0};
 fronts[1]=(struct fixture_frontier){0,0,0,0};
 fronts[2]=(struct fixture_frontier){(uintptr_t)duplicates,(uintptr_t)(duplicates+67),(uintptr_t)(duplicates+67),0};
 *(uintptr_t*)(seq+104)=(uintptr_t)fronts;*(int*)(seq+112)=3;
 memcpy(seq+120,&(struct fixture_frontier){(uintptr_t)invariants,(uintptr_t)(invariants+65),(uintptr_t)(invariants+65),0},32);
 struct run_state*s=&runs[0];s->id=1;s->live=true;s->seq=(uintptr_t)seq;register_run(s);ds(s);semantic_contract(s);fixture_epoch_begin(s);
 bool wide=!strcmp(argv[2],"wide");
 if(wide)cubes[10].packed=0xffffffffU;
 unsigned steps=wide?1:!strcmp(argv[2],"short")?5:!strcmp(argv[2],"large")?2:300;
 for(unsigned j=0;j<steps;j++){
  if(j==1)cubes[10].packed=0xffffffffU; /* Same cube, changed negative level + flag. */
  if(j==2){uintptr_t tmp=items[0];items[0]=items[100];items[100]=tmp;}
  if(j==3)fronts[0].end=(uintptr_t)(items+FIXTURE_CUBES-1);
  if(j==4)fronts[0].end=(uintptr_t)(items+FIXTURE_CUBES);
  if(!strcmp(argv[2],"churn")&&j>=5){
   size_t count=(fronts[0].end-fronts[0].begin)/8;
   if(j%2){size_t mid=count/2;memmove(items+mid,items+mid+1,(count-mid-1)*8);fronts[0].end-=8;}
   else{assert(count<FIXTURE_CUBES);memmove(items+1,items,count*8);items[0]=(uintptr_t)&cubes[(j*37)%FIXTURE_CUBES];fronts[0].end+=8;}
  }
  snapshot(s);
 }
 if(!wide&&strcmp(argv[2],"large")){fixture_epoch_begin(s);snapshot(s);}
 /* Exercise bounded-cache eviction without a solver or a large history vector. */
#ifdef FRAME_CHUNK_CACHE
 if(frame_chunks_enabled&&!strcmp(argv[2],"evict")){
  unsigned char tuple[12];uint64_t cube=full_cube(s,(uintptr_t)&cubes[0]);
  for(unsigned j=0;j<FRAME_CHUNK_CACHE+3;j++){
   frame_le(tuple,cube,8);frame_le(tuple+8,j,4);assert(frame_chunk(s,tuple,1));
  }
  assert(g_hash_table_size(s->detail->frame_chunks)<=FRAME_CHUNK_CACHE);
  snapshot(s);
 }
 #endif
 if(!strcmp(argv[2],"badread")||!strcmp(argv[2],"retry")){
  uint32_t raw=0xabcdef02U;struct fixture_cube extra={(uintptr_t)&raw,1,0,7};
  unsigned before=g_hash_table_size(s->detail->members);
  items[0]=(uintptr_t)&extra;items[5]=1;
  frame_snapshot(s,"fixture_failed_read",0);
  assert(g_hash_table_size(s->detail->members)==before); /* Roll back additions. */
  if(!strcmp(argv[2],"retry")){
   items[5]=(uintptr_t)&cubes[5];
   snapshot(s); /* The formerly provisional extra must be added again. */
  }
 }
 emit(s,"final",true,"result=valid lost=%"PRIu64" read_failures=%"PRIu64" callback_failures=0",s->lost,s->read_failures);semantic_seal(s);
 fprintf(stderr,"FIXTURE chunks_cached=%u cubes_cached=%u members_live=%u records=%"PRIu64" read_failures=%"PRIu64"\n",
#ifdef FRAME_CHUNK_CACHE
 g_hash_table_size(s->detail->frame_chunks),
#else
 0U,
#endif
 g_hash_table_size(s->detail->cubes),g_hash_table_size(s->detail->members),s->records,s->read_failures);
 destroy_details(s);fclose(oracle);close_disk_sinks();write_worker_manifest(true);return 0;
}
