#!/usr/bin/env python3
"""Finite, exhaustive tests of the source-derived interpretation rules.
These are mathematical regression models, not purported native Jasper runs or
proof of arbitrary telemetry/RTL equivalence. No SAT result is reclassified.
"""
from pathlib import Path
import argparse, json


def reachable(initial, edges):
    seen=set(initial)
    while True:
        larger=seen | {y for x,y in edges if x in seen}
        if larger==seen:return seen
        seen=larger


def run():
    tests=[];counterexamples=[];checked=0;inductive=0
    universe=set(range(3)); possible=[(x,y) for x in universe for y in universe]
    for tm in range(1<<len(possible)):
        edges={e for i,e in enumerate(possible) if tm>>i&1}
        for im in range(8):
            initial={x for x in universe if im>>x&1};reach=reachable(initial,edges)
            for cm in range(8):
                clause={x for x in universe if cm>>x&1};checked+=1
                base=initial<=clause
                step=all(x not in clause or y in clause for x,y in edges)
                if base and step:
                    inductive+=1
                    assert reach<=clause
                # The UNSAT predecessor query is stronger than the query
                # that additionally assumes the current blocking clause.
                for fm in range(8):
                    frame={x for x in universe if fm>>x&1}
                    exclusion=not any(x in frame and y not in clause for x,y in edges)
                    relative=not any(x in frame and x in clause and y not in clause for x,y in edges)
                    assert not exclusion or relative
                    if relative and base and initial<=frame and not reach<=clause and len(counterexamples)<3:
                        counterexamples.append(dict(I=sorted(initial),F=sorted(frame),C=sorted(clause),T=sorted(edges),reachable=sorted(reach)))
    assert counterexamples
    tests.append({'name':'initiation_and_global_step_imply_reachable_invariance','status':'PASS','transition_systems_times_initial_and_clause_sets':checked,'inductive_cases':inductive})
    tests.append({'name':'frame_relative_UNSAT_is_not_global_invariance','status':'PASS','exhaustive_relative_contexts':checked*8,'counterexamples':counterexamples})
    # Meaningful three-state example with an initiated, nonempty frame:
    I={0};F={0};C={0,1};T={(0,1),(1,2),(2,2)}
    assert I<=F and I<=C
    assert not any(x in F and x in C and y not in C for x,y in T)
    assert 2 in reachable(I,T) and 2 not in C
    tests.append({'name':'explicit_relative_clause_trap','status':'PASS','candidate':'x != 2','frame':'x == 0','local_query':'UNSAT','concrete_violating_path':[0,1,2],'required_action':'Do not promote; check the global step and reachable counterexample.'})
    # Credit accounting: P alone is not inductive; L supplies the missing relation.
    depth=31;width=6;mask=(1<<width)-1
    def successors(s):
        used,free=s;result=[]
        for push,pop in ((0,0),(0,1),(1,0),(1,1)):
            if push and not pop and free:
                nxt=((used+1)&mask,free-1)
            elif pop and not push and used:
                nxt=(used-1,(free+1)&mask)
            else:nxt=s
            result.append((push,pop,nxt))
        return result
    all_states={(u,f) for u in range(mask+1) for f in range(mask+1)}
    L=lambda s:s[0]+s[1]==depth # widened sum, NOT modulo 2**width
    P=lambda s:s[0]<=depth
    initial={(0,depth)};seen=set(initial);front=set(initial)
    while front:
        new={n for s in front for _,_,n in successors(s)}-seen
        seen |= new;front=new
    assert len(seen)==32 and all(L(s) and P(s) for s in seen)
    assert all(L(s) for s in initial)
    assert all(not L(s) or all(L(n) for _,_,n in successors(s)) for s in all_states)
    assert all(not L(s) or P(s) for s in all_states)
    trap=(31,1);bad=successors(trap)[2][2]
    assert P(trap) and not P(bad) and trap not in seen and not L(trap)
    tests.append({'name':'useful_joint_strengthening_credit_conservation','status':'PASS','states_exhausted':4096,'transition_cases':16384,'reachable_states':32,'L':'widened(used)+widened(free)==31','P':'used<=31','P_inductive_alone':False,'counterexample_to_induction':{'before':trap,'push':1,'pop':0,'after':bad,'reachable':False},'L_base':True,'L_step':True,'L_implies_P':True,'engine_performance_benefit':'NOT_MEASURED','inferred_automatically_from_capture':False})
    # A tautological helper is valid but cannot remove the bad induction step.
    D=lambda s:0<=s[0]<=mask
    assert all(D(s) for s in all_states) and D(trap)
    tests.append({'name':'valid_but_inert_distractor','status':'PASS','D':'0<=used<=63','valid':True,'eliminates_step_counterexample':False})
    # Existential abstraction projecting away free is an overapproximation, but
    # admits a spurious 0,1,...,32 path. Refinement must not cut concrete paths.
    abstract_edges={(s[0],n[0]) for s in all_states for _,_,n in successors(s)}
    abstract_path=list(range(33))
    assert all((x,y) in abstract_edges for x,y in zip(abstract_path,abstract_path[1:]))
    concrete_front=initial
    for desired in abstract_path[1:]:concrete_front={n for s in concrete_front for _,_,n in successors(s) if n[0]==desired}
    assert not concrete_front
    refined_edges={(s[0],n[0]) for s in all_states if L(s) for _,_,n in successors(s)}
    assert all((s[0],n[0]) in refined_edges for s in seen for _,_,n in successors(s))
    assert (31,32) not in refined_edges
    tests.append({'name':'abstract_CEX_requires_concretization','status':'PASS','abstract_path':abstract_path,'concrete_realizations':0,'refinement':'certified conservation relation L','all_concrete_reachable_steps_preserved':True})
    # Same transition system: a genuinely false bound is reached, not repaired
    # with an invalid strengthening.
    concrete=(0,31);path=[concrete]
    for i in range(16):concrete=successors(concrete)[2][2];path.append(concrete)
    assert path[-1][0]>15 and all(s in seen for s in path)
    tests.append({'name':'real_CEX_is_not_a_strengthening_problem','status':'PASS','false_property':'used<=15','concrete_inputs':'16 consecutive pushes','concrete_path':path,'violation_step':16})
    return {'schema':1,'status':'PASS','tests':tests,'test_count':len(tests),'method':'finite exhaustive enumeration of the stated mathematical models','native_Jasper_run':False,'arbitrary_RTL_equivalence_claimed':False}

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    result=run();a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(json.dumps(result,indent=2)+'\n');print('PASS',result['test_count'],'mathematical regressions')
