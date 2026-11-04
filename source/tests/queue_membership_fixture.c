/* Regression for node-address recycling, not a Jasper proof. */
#ifndef QUEUE_PRODUCER_FILE
#define QUEUE_PRODUCER_FILE "../src/events.c"
#endif
#include QUEUE_PRODUCER_FILE
int main(void){
 gum_init_embedded();disk_only=true;compress_disk=true;capture_identity();
 struct run_state*s=&runs[0];s->id=1;s->live=true;register_run(s);
 struct detailed_state*d=ds(s);GHashTable*next=g_hash_table_new(g_direct_hash,g_direct_equal);
 gpointer a=(gpointer)(uintptr_t)0x1000,b=(gpointer)(uintptr_t)0x2000;
 g_hash_table_insert(d->nodes,a,(gpointer)(uintptr_t)11);
 g_hash_table_insert(d->nodes,b,(gpointer)(uintptr_t)22);
 g_hash_table_insert(next,a,(gpointer)(uintptr_t)33); /* same node, new obligation */
 g_hash_table_insert(next,b,(gpointer)(uintptr_t)22); /* same membership */
 queue_membership_removals(s,next,1,"fixture",1);
 if(d->observed_dequeues!=1){fprintf(stderr,"missing queue removal for recycled list node\n");return 3;}
 g_hash_table_destroy(d->nodes);d->nodes=next;
 next=g_hash_table_new(g_direct_hash,g_direct_equal);
 g_hash_table_insert(next,a,(gpointer)(uintptr_t)33);
 queue_membership_removals(s,next,2,"fixture",2);
 if(d->observed_dequeues!=2)return 4; /* only obligation 22 removed */
 g_hash_table_destroy(d->nodes);d->nodes=next;
 next=g_hash_table_new(g_direct_hash,g_direct_equal);
 queue_membership_removals(s,next,3,"fixture",3);
 if(d->observed_dequeues!=3)return 5; /* only obligation 33 removed */
 g_hash_table_destroy(next);close_disk_sinks();write_worker_manifest(true);
 return 0;
}
