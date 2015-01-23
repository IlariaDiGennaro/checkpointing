#include "tracking_accesses.h"

//structure
bucket_data buckets[NBUCKETS];

//update_structure
void update_hashbucket(void * fault_address,unsigned char pgd_index){
			
	unsigned int bucket_index = HASH_FUNCTION(fault_address);
	#define bucket (buckets[bucket_index])
	while(cmpxchg(&(bucket.spinlock),0,1)); //while(lock==1)==while(locked)
	printk("bucket_index=%d\n",bucket_index);
	printk("key_zone=%d\n",ZONE2M(fault_address));
	printk("pte=%d\n",PTE(fault_address));
	printk("pde_relative=%d\n",PDE(fault_address));
	node * a_node;
	if(!CHECK_NODE(NODE_BIT(PDE(fault_address)),bucket.nodes_tracking)) {
		a_node=kzalloc(SIZE_NODE,GFP_KERNEL);
		(a_node -> h).key_zone = ZONE2M(fault_address);
		(a_node->h).next_node = bucket.nodes_list;
		(bucket.nodes_list) = (void *)a_node;
		set_bit(NODE_BIT(PDE(fault_address)),&(bucket.nodes_tracking));
		goto update_body;
	}
	else {
		a_node = (node *)(bucket.nodes_list);
		while((a_node->h).next_node!=NULL) {
			if((a_node->h).key_zone == ZONE2M(fault_address))
				goto update_body;
			a_node = (node *) ((a_node->h).next_node);
		}
		if((a_node->h).key_zone==ZONE2M(fault_address))
			goto update_body;
	}
	
	update_body:
	update_body(pgd_index, a_node,PTE(fault_address));
	end_add_node: cmpxchg(&(bucket.spinlock),1,0); //unlocked
	#undef bucket
	return;	
}
	
//audit_structure
void audit_hashbucket() {
	unsigned int i,j,k;
	for(i=0; i<NBUCKETS; i++) {
		bucket_data bd = buckets[i];
		if((bd.nodes_tracking)>0) {
			printk("bucket data n° %d=%u\n",i,bd.nodes_tracking);
			for(k=0;k<N_NODES_PER_BUCKET;k++) {
				unsigned int ctb = CHECK_NODE(k,bd.nodes_tracking);
				if(ctb)
					printk("bit %d = %d\n",k,ctb);
			}
			node * a_node = (node*)bd.nodes_list;
			print_body(a_node);
		}
	}
}
