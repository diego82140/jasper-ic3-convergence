// Observation-ABI test fixture, NOT Jasper and NOT a model-checker proof.
// This executable deliberately contains no logging formatters used by the DSO.
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cassert>
#include <cstring>
#include <setjmp.h>
static jmp_buf fixture_jump;
class Jip;struct ICSeq;
__attribute__((noinline)) void fixture_probe(Jip&,ICSeq&){asm volatile("" ::: "memory");}
struct Formula {uint32_t data;};
template<class T> struct vec {T* data;int sz;int cap;};
class lbool {public:int value;constexpr lbool(int v):value(v){};};
static const lbool l_True(1),l_False(-1),l_Undef(0);
enum Result {PR_Valid,PR_Cex,PR_Undetermined};
struct ProofResult {Result _result;int _note;char pad[16];unsigned _length;};
enum SolverResult {MODEL,UNSAT,UNSAT_ASSUME,UNDETERMINED,TIMEOUT};
struct ICSeq {int k=0,obligations=0;};
struct ICHeapMgr {};
struct ICTrace {};
class JipCallbackHook {public:virtual ~JipCallbackHook()=default;virtual void report(const char* text,unsigned ix,bool console){(void)ix;(void)console;std::puts(text);}};
struct JSolver {int calls=0;
 __attribute__((noinline)) SolverResult solveLimited(const vec<Formula>& a,int budget,bool avoid);
};
SolverResult JSolver::solveLimited(const vec<Formula>& a,int budget,bool avoid){
 (void)budget;(void)avoid;calls++;return a.data[0].data%3==0?UNSAT:a.data[0].data%3==1?MODEL:TIMEOUT;
}
class Jip {
 public:JipCallbackHook *callback;JSolver solver;int modified=0;
 explicit Jip(JipCallbackHook*c):callback(c){}
 __attribute__((noinline)) bool ic_init_solver(ICSeq&);
 __attribute__((noinline)) void ic_init_level(ICSeq&);
 __attribute__((noinline)) lbool ic_solve_relative(ICSeq&,int,unsigned,vec<Formula>&,vec<Formula>*);
 __attribute__((noinline)) lbool ic_refineinit_solve_relative(ICSeq&,int,unsigned,vec<Formula>&,vec<Formula>*);
 __attribute__((noinline)) void ic_stats(ICSeq&,const ProofResult&);
 __attribute__((noinline)) bool ic_generalize(vec<Formula>&,int,ICSeq&);
 __attribute__((noinline)) bool ic_block(vec<Formula>&,ICTrace&,ICSeq&,ICHeapMgr&);
 __attribute__((noinline)) bool ic_process_proof_obl(ICHeapMgr&,ICTrace&,int&,ICSeq&);
 enum IcPushMode {Ordinary};
 __attribute__((noinline)) bool ic_push(ICSeq&,bool,IcPushMode);
 __attribute__((noinline)) void ic_fixture_driver(ICSeq&,vec<Formula>&,const char*);
};
bool Jip::ic_init_solver(ICSeq&f){f.k=0;return true;}
void Jip::ic_init_level(ICSeq&f){f.k++;}
lbool Jip::ic_solve_relative(ICSeq&f,int frame,unsigned flags,vec<Formula>&conjs,vec<Formula>*removed){
 (void)f;(void)flags;(void)conjs;(void)removed;
 Formula value{(uint32_t)frame};vec<Formula>a{&value,1,1};
 SolverResult result=solver.solveLimited(a,-1,true);
 if(std::getenv("FIXTURE_UNWIND")&&frame==3)throw 5;
 if(std::getenv("FIXTURE_UNWIND")&&frame==5)ic_solve_relative(f,3,flags,conjs,removed);
 if(std::getenv("FIXTURE_UNWIND")&&frame==6){try{ic_solve_relative(f,3,flags,conjs,removed);}catch(int value){assert(value==5);}}
 if(std::getenv("FIXTURE_UNWIND")&&frame==7)longjmp(fixture_jump,5);
 if(std::getenv("FIXTURE_UNWIND")&&frame==4)ic_solve_relative(f,0,flags,conjs,removed);
 return result==MODEL?l_True:result==UNSAT?l_False:l_Undef;
}
void Jip::ic_stats(ICSeq&f,const ProofResult&r){modified+=f.k+(r._result==PR_Valid?1:2);}
__attribute__((optimize("O2"))) lbool Jip::ic_refineinit_solve_relative(ICSeq&f,int frame,unsigned flags,vec<Formula>&c,vec<Formula>*removed){return ic_solve_relative(f,frame,flags,c,removed);}
bool Jip::ic_generalize(vec<Formula>&c,int frame,ICSeq&f){if(std::getenv("FIXTURE_UNWIND")&&frame==3)ic_solve_relative(f,3,1,c,nullptr);if(c.sz>1){c.sz--;return true;}return false;}
bool Jip::ic_block(vec<Formula>&c,ICTrace&t,ICSeq&f,ICHeapMgr&h){int n=0;(void)c;return ic_process_proof_obl(h,t,n,f);}
bool Jip::ic_process_proof_obl(ICHeapMgr&,ICTrace&,int&n,ICSeq&f){n++;f.obligations++;return true;}
bool Jip::ic_push(ICSeq&f,bool early,IcPushMode mode){(void)mode;return early&&f.k>0;}
void Jip::ic_fixture_driver(ICSeq&f,vec<Formula>&cube,const char*mode){
 try{
  if(!std::strcmp(mode,"generalize"))ic_generalize(cube,3,f);
  else if(!std::strcmp(mode,"recursive_throw"))ic_solve_relative(f,5,1,cube,nullptr);
  else if(!std::strcmp(mode,"selfcatch"))assert(ic_solve_relative(f,6,1,cube,nullptr).value==-1);
  else if(!std::strcmp(mode,"longjmp")){int jumped=setjmp(fixture_jump);if(!jumped)ic_solve_relative(f,7,1,cube,nullptr);else assert(jumped==5);}
  else ic_solve_relative(f,3,1,cube,nullptr);
 }catch(int value){assert(value==5);}
 if(!std::strcmp(mode,"second_throw")){try{ic_solve_relative(f,3,1,cube,nullptr);}catch(int value){assert(value==5);}}
 if(!std::strcmp(mode,"ancestor"))return;
 if(!std::strcmp(mode,"probe"))fixture_probe(*this,f);
 Formula x{1};vec<Formula>a{&x,1,1};assert(solver.solveLimited(a,-1,true)==MODEL);
 assert(ic_init_solver(f));
 for(int frame=0;frame<3;frame++)assert(ic_solve_relative(f,frame,1,cube,nullptr).value==(frame==0?-1:frame==1?1:0));
 if(!std::strcmp(mode,"recursive"))assert(ic_solve_relative(f,4,1,cube,nullptr).value==1);
 if(!std::strcmp(mode,"tail"))assert(ic_refineinit_solve_relative(f,1,1,cube,nullptr).value==1);
 if(!std::strcmp(mode,"two_runs")){
  ICSeq other;assert(ic_init_solver(other));assert(ic_solve_relative(other,1,1,cube,nullptr).value==1);
  ProofResult r{PR_Valid,0,{0},0};ic_stats(other,r);
  assert(ic_solve_relative(f,1,1,cube,nullptr).value==1);
 }
}
int main(){
 JipCallbackHook cb;Jip jip(&cb);
 if(const char*mode=std::getenv("FIXTURE_UNWIND")){
  ICSeq f;assert(jip.ic_init_solver(f));
  Formula a[3]{{0},{8},{16}};vec<Formula>cube{a,3,3};
  jip.ic_fixture_driver(f,cube,mode);
  if(!std::strcmp(mode,"ancestor")){assert(jip.ic_init_solver(f));assert(jip.ic_solve_relative(f,1,1,cube,nullptr).value==1);}
  ProofResult r{PR_Valid,0,{0},0};jip.ic_stats(f,r);
  assert(jip.callback==&cb);
  std::printf("FIXTURE_UNWIND_OK mode=%s calls=%d modified=%d\n",mode,jip.solver.calls,jip.modified);
  return 0;
 }
 for(int round=0;round<2;round++){
  ICSeq f;assert(jip.ic_init_solver(f));jip.ic_init_level(f);
  Formula a[257];for(unsigned i=0;i<257;i++)a[i].data=(i<<3)|((i&1)?4:0);vec<Formula>cube{a,257,257};
  for(int frame=0;frame<3;frame++){
   int r=jip.ic_solve_relative(f,frame,1,cube,nullptr).value;
   assert(r==(frame==0?-1:frame==1?1:0));
  }
  assert(jip.ic_generalize(cube,0,f));assert(cube.sz==256);
  ICTrace t;ICHeapMgr h;assert(jip.ic_block(cube,t,f,h));assert(f.obligations==1);
  assert(jip.ic_push(f,true,Jip::Ordinary));
  if(std::getenv("FIXTURE_EARLY_EXIT"))std::exit(0); // closed transport, native run unsealed
  ProofResult r{round?PR_Cex:PR_Valid,0,{0},0};jip.ic_stats(f,r);
  if(std::getenv("FIXTURE_ABORT_AFTER_SEAL"))std::_Exit(0); // emulate native engine cancellation: no ELF destructors
 }
 assert(jip.solver.calls==6&&jip.modified==5&&jip.callback==&cb);
 std::puts("FIXTURE_RESULTS_OK calls=6 modified=5");
}
