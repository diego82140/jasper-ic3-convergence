/* Actual collector code on explicit synthetic objects, not a Jasper ABI proof. */
#ifndef PAYLOAD_PRODUCER_FILE
#define PAYLOAD_PRODUCER_FILE "../src/events.c"
#endif
#include PAYLOAD_PRODUCER_FILE
#include <assert.h>
struct fixture_cube {uintptr_t data;int count,capacity;};
struct fixture_po {uint32_t flags;int path;uintptr_t cube,parent;};
int main(void){
 gum_init_embedded();disk_only=true;compress_disk=true;capture_identity();
 P.cube_data=0;P.cube_size=8;P.details=0;
 struct run_state*s=&runs[0];s->id=1;s->live=true;register_run(s);
 struct detailed_state*d=ds(s);uint32_t values[]={8,12,0xffffffffU};
 uint64_t id=capture_vector_data(s,(uintptr_t)values,3,"jip_formula");assert(id);
 assert(capture_vector_data(s,(uintptr_t)values,3,"jip_formula")==id);
 GHashTableIter it;gpointer key,value;g_hash_table_iter_init(&it,d->cubes);
 assert(g_hash_table_iter_next(&it,&key,&value));
 /* Simulate a hash collision without assuming a practical SHA256 attack. */
 ((struct cube_definition*)value)->values[0]^=4;
 uint64_t replacement=capture_vector_data(s,(uintptr_t)values,3,"jip_formula");assert(replacement&&replacement!=id);
 values[0]=16;uint64_t limit=record_limit;record_limit=s->records+1;
 assert(!capture_vector_data(s,(uintptr_t)values,3,"jip_formula"));
 uint64_t incomplete=d->cube_ids;record_limit=limit;
 assert(capture_vector_data(s,(uintptr_t)values,3,"jip_formula")>incomplete);
 unsigned char tuples[12]={1,0,0,0,0,0,0,0,0xff,0xff,0xff,0xff};
 uint64_t chunk=frame_chunk(s,tuples,1);assert(chunk);
 g_hash_table_iter_init(&it,d->frame_chunks);assert(g_hash_table_iter_next(&it,&key,&value));
 ((struct frame_chunk_definition*)value)->tuples[0]^=1;
 assert(frame_chunk(s,tuples,1)>chunk);
 struct fixture_cube cube={(uintptr_t)values,3,3};
 struct fixture_po parent={4,1,(uintptr_t)&cube,0},child={0,2,(uintptr_t)&cube,(uintptr_t)&parent};
 uint64_t po=define_po(s,(uintptr_t)&child);assert(po);
 struct po_definition*observed=g_hash_table_lookup(d->pos,&child);uint64_t previous=observed->cube_id;
 values[0]^=4;assert(define_po(s,(uintptr_t)&child)==po);assert(observed->cube_id!=previous);
 parent.flags=12;assert(define_po(s,(uintptr_t)&child)==po);
 assert(((struct po_definition*)g_hash_table_lookup(d->pos,&parent))->flags==12);
 parent.parent=(uintptr_t)&child;assert(!define_po(s,(uintptr_t)&child));parent.parent=0;
 /* Failed queue payloads must preserve the previously confirmed baseline. */
 unsigned char manager[176]={0},tree[64]={0},node[24]={0};P.details=1;full_snapshots=true;
 d->heap=(uintptr_t)manager;*(int*)(manager+52)=1;*(uintptr_t*)(manager+80)=(uintptr_t)tree;
 *(uintptr_t*)(tree+40)=(uintptr_t)node;*(uintptr_t*)node=(uintptr_t)(tree+40);
 *(uintptr_t*)(node+16)=(uintptr_t)&child;child.cube=1;
 g_hash_table_insert(d->nodes,(gpointer)0x1000,(gpointer)99);GHashTable*baseline=d->nodes;
 queue_snapshot(s,"sample",1);assert(d->nodes==baseline&&g_hash_table_lookup(d->nodes,(gpointer)0x1000)==(gpointer)99);
 /* The real hook must read the current payload, not trust the old cache. */
 child.cube=(uintptr_t)&cube;current=s;
 uint64_t child_id=((struct po_definition*)g_hash_table_lookup(d->pos,&child))->id;
 struct fixture_po undefined={0};reserve_po(s,(uintptr_t)&undefined);
 for(int mode=0;mode<7;mode++){
  gpointer observed_node=mode==5?(gpointer)1:node;
  g_hash_table_insert(d->nodes,observed_node,(gpointer)(uintptr_t)child_id);
  *(uintptr_t*)(node+16)=mode==0?(uintptr_t)&child:mode==1?(uintptr_t)&parent:mode==2?0:mode==3?1:(uintptr_t)&cube;
  if(mode==6)*(uintptr_t*)(node+16)=(uintptr_t)&undefined;
  uint64_t failures=s->read_failures,dequeues=d->observed_dequeues;
  record_queue_unlink(s,(uintptr_t)observed_node);
  if(!mode){assert(!g_hash_table_contains(d->nodes,observed_node));assert(d->observed_dequeues==dequeues+1);}
  else{assert(g_hash_table_contains(d->nodes,observed_node));assert(d->observed_dequeues==dequeues);assert(s->read_failures>failures);}
 }
 /* Two distinct list nodes may hold the same PO. One physical node may not
  * stand for two occurrences in a complete native snapshot. */
 unsigned char other_tree[64]={0},other_node[24]={0};
 *(uintptr_t*)(manager+144)=(uintptr_t)other_tree;*(int*)(manager+116)=1;
 *(uintptr_t*)(other_tree+40)=(uintptr_t)other_node;*(uintptr_t*)other_node=(uintptr_t)(other_tree+40);
 *(uintptr_t*)(other_node+16)=(uintptr_t)&child;*(uintptr_t*)(node+16)=(uintptr_t)&child;
 queue_snapshot(s,"sample",2);assert(g_hash_table_size(d->nodes)==2);
 assert(g_hash_table_lookup(d->nodes,node)==g_hash_table_lookup(d->nodes,other_node));
 baseline=d->nodes;*(uintptr_t*)(manager+144)=(uintptr_t)tree;
 queue_snapshot(s,"sample",3);assert(d->nodes==baseline);
 /* Qualify only the borrowed manager reference in a live matching call. */
 struct hook borrow_hook={.kind=H_BLOCK};struct observer_activation borrow={0};
 borrow.hook=&borrow_hook;borrow.call.state=s;borrow.call.manager=(uintptr_t)manager;borrow.generation=s->id;borrow.token=77;
 struct observer_activation*saved_top=observer_top;observer_top=&borrow;const char*role=NULL;
 assert(queue_owner_reference(s,(uintptr_t)manager,(uintptr_t)manager+48,&role)==77&&!strcmp(role,"short"));
 assert(queue_owner_reference(s,(uintptr_t)manager,(uintptr_t)manager+112,&role)==77&&!strcmp(role,"long"));
 assert(!queue_owner_reference(s,(uintptr_t)manager,(uintptr_t)manager+49,&role)&&!strcmp(role,"unqualified"));
 borrow.generation++;assert(!manager_reference_activation(s,(uintptr_t)manager));borrow.generation--;
 borrow_hook.kind=H_QUEUEPUSH;assert(!manager_reference_activation(s,(uintptr_t)manager));
 borrow_hook.kind=H_BLOCK;s->run_unwound=true;assert(!manager_reference_activation(s,(uintptr_t)manager));s->run_unwound=false;
 observer_top=saved_top;
 close_disk_sinks();write_worker_manifest(true);
 puts("PASS exact cube/frame cache equality, incomplete retry, in-place payload/ancestor refresh, cycle rejection, queue rollback");
 return 0;
}
