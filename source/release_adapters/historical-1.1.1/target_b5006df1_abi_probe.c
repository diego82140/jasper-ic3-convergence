/* TEST ONLY. Runs actual user-worker routines against explicit ABI fixtures.
 * This is not a native Jasper proof, nor is the lower solver a SAT solver.
 * No target ELF bytes are changed. The library under test supplies all telemetry.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
__asm__(".symver dlsym,dlsym@GLIBC_2.2.5");

static _Alignas(16) unsigned char jip[2048],seq[2048],config[2048],jsolver[2048],circ[256],callback[64],sink[16];
static void* sinkvt[100];
static void* solvervt[64];
static struct {void**vt;} solver={solvervt};
static void* solverarray[32];
static struct {uint32_t*data;int sz,cap;} cube={0};
static unsigned records,bridge_calls,solver_calls, failures;
static int result_raw,expected_budget,expected_assumptions,expected_literal;
static uint32_t lit_values[2]={2,4};
static struct {uint32_t*data;int sz,cap;} lit_entry={lit_values,2,2};
static void *lit_map[16];
static uint32_t formula=0x10;
static unsigned char modelinfo[64];
static void require(bool b,const char*txt);
static void *fixture_model(void*self){require(self==&solver,"model object pointer");return calloc(1,16);}
static void p64(void*p,size_t n,void*v){memcpy((char*)p+n,&v,sizeof v);}
static void p32(void*p,size_t n,int v){memcpy((char*)p+n,&v,4);}
static int g32(void*p,size_t n){int v;memcpy(&v,(char*)p+n,4);return v;}
static void require(bool b,const char*txt){if(!b){fprintf(stderr,"ABI_ASSERT_FAIL %s\n",txt);++failures;}}

static void capture(void*self,const char*text,unsigned index,bool console){
 require(self==sink,"native bridge sink pointer");
 require(index==0,"native bridge event index");
 require(console==true,"native bridge console bool");
 if(!strncmp(text,"IC3_STATS ",10)){
  ++records;puts(text);
  require(strstr(text,"origin=preload")!=NULL,"record produced by preload, not target");
 }
 ++bridge_calls;
}
static int fixture_solve(void*self,void*assumptions,int budget,bool flag){
 /* Native target solveLimited copies the input into a std::vector<uint32_t>. */
 uintptr_t*vec=assumptions;
 require(self==&solver,"solver object pointer");
 require(vec[1]-vec[0]==(uintptr_t)(expected_assumptions*4),"assumption count preserved");
 if(expected_assumptions)require(*(uint32_t*)vec[0]==(uint32_t)expected_literal,"converted assumption literal preserved");
 require(budget==expected_budget,"solver budget preserved");
 require(flag==true,"solver result checking flag");
 ++solver_calls;
 return result_raw;
}
static void setup(void){
 memset(jip,0,sizeof jip);memset(seq,0,sizeof seq);memset(config,0,sizeof config);memset(jsolver,0,sizeof jsolver);memset(circ,0,sizeof circ);
 sinkvt[0x2d8/8]=(void*)capture;
 p64(sink,0,sinkvt);
 /* ACTUAL Bullet JipCallbackHook vtable in the target, NOT a fabricated JIP vtable. */
 p64(callback,0,(void*)0x1d66990);
 p64(callback,0x28,sink);
 p64(jip,0x1e0,callback);p64(jip,0x38,jsolver);p64(jip,0x40,circ);
 p32(jip,0x1e8,0);
 p64(seq,0,config);
 p32(seq,200,4);p32(seq,280,37);p32(seq,272,11);p32(seq,276,12);p32(seq,284,13);
 solvervt[19]=(void*)fixture_solve;
 solvervt[25]=(void*)fixture_model;
 p32(modelinfo,16,-1);p64(jsolver,0x58,modelinfo);
 for(unsigned n=0;n<32;n++)solverarray[n]=&solver;
 p64(seq,80,solverarray);p32(seq,88,32);
 p64(jsolver,0x78,&solver);
 for(unsigned n=0;n<16;n++)lit_map[n]=&lit_entry;
 p64(jsolver,0x28,lit_map);p32(jsolver,0x30,16);
}
static int probe_main(int argc,char**argv,char**env){
 (void)argc;(void)argv;(void)env;
 setvbuf(stdout,NULL,_IOLBF,0);
 puts("TARGET_ABI_PROBE: real target functions; fixture lower solver; NOT a Jasper proof");
 setup();
 unsigned char before[sizeof jip];memcpy(before,jip,sizeof jip);
 int (*relative)(void*,void*,int,unsigned,void*,void*)=(void*)0x16ea700;
 int (*clone1)(void*,void*,int,void*)=(void*)0x16ee250;
 int (*clone0)(void*,void*,int,void*)=(void*)0x16ee670;
 int expected[4]={1,-1,-1,0};
 for(unsigned nonempty=0;nonempty<2;nonempty++){
  cube.data=nonempty?&formula:NULL;cube.sz=cube.cap=nonempty;
  for(unsigned variant=0;variant<4;variant++){
  for(int raw=0;raw<4;raw++){
   result_raw=raw;expected_budget=variant==1?1000:-1;
   expected_assumptions=nonempty;expected_literal=4;
   errno=EDOM;
   int r=variant<2?relative(jip,seq,0,variant==1?8:0,&cube,NULL):(variant==2?clone1(jip,seq,0,&cube):clone0(jip,seq,0,&cube));
   printf("ABI_RESULT nonempty=%u variant=%u raw=%d relative=%d expected=%d\n",nonempty,variant,raw,r,expected[raw]);
   require(r==expected[raw],"relative lbool encoding");
   require(g32(jip,0x1e8)==0,"debug selector remains zero");
  }
 }
 }
 bool (*generalize)(void*,void*,int,void*)=(void*)0x16ebbc0;
 for(int n=0;n<2;n++){
  cube.data=n?&formula:NULL;cube.sz=cube.cap=n;
  bool changed=generalize(jip,&cube,0,seq);
  require(!changed,"native generalization of <=1 literal returns false");
  require(cube.sz==n,"small cube preserved by native generalizer");
 }
 require(g32(seq,284)==15,"native generalize counter offset");
 require(g32(seq,288)==32,"native relative call counter offset");
 require(g32(seq,292)==8,"native SAT counter offset");
 require(solver_calls==32,"one native lower solve per relative query");
 require(!memcmp(before,jip,sizeof jip),"observer/JIP object bytes stable during these functions");
 unsigned char proof[32]={0};p32(proof,0,1);
 void (*stats)(void*,void*,const void*)=(void*)0x16db140;
 stats(jip,seq,proof);
 if(getenv("EXPECT_PRELOAD"))require(records>0,"preload generated records on marker-free target");
 require(records==bridge_calls,"native reporting bridge delivery");
 printf("TARGET_ABI_PROBE_%s calls=%u records=%u failures=%u\n",failures?"FAIL":"PASS",solver_calls,records,failures);
 return failures?1:0;
}
int __libc_start_main(int (*mainfn)(int,char**,char**),int argc,char**argv,void(*init)(void),void(*fini)(void),void(*rtld)(void),void*end){
 (void)mainfn;
 typedef int(*start_t)(int(*)(int,char**,char**),int,char**,void(*)(void),void(*)(void),void(*)(void),void*);
 start_t f=(start_t)dlsym(RTLD_NEXT,"__libc_start_main");
 if(!f)_exit(125);
 return f(probe_main,argc,argv,init,fini,rtld,end);
}
