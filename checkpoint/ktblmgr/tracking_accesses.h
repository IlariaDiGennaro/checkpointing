/* 1-ZONE_SINGLE_ACCESS: tracciamento dell'accesso a zone di granularità 2 mega da parte di 64 thread
 * 2-ZONE_MULTI_ACCESS: tracciamento degli accessi (contatore) a zone di granularità 2 mega da parte di 64 thread
 * 3-PAGE_SINGLE_ACCESS: tracciamento dell'accesso a pagine di 4k da parte di 64 thread
 * 4-PAGE_MULTI_ACCESS: tracciamento degli accessi (contatore) a pagine di 4k da parte di 64 thread*/
  
 #ifndef __TRACKING_ACCESSES_H
 	#define __TRACKING_ACCESSES_H
 	
 	#include <linux/module.h>
	#include <linux/kernel.h>
 	
 	#define PDE(addr)  (((long long)(addr) >> 21) & 0x1ff)
	#define PTE(addr)  (((long long)(addr) >> 12) & 0x1ff)
	
	#define NZONE2M (71303168)
	#define NBUCKETS (1114112)
	#define N_NODES_PER_BUCKET (64)
	#define N_NODES_PER_BUCKET_LOG (6)
	#define HASH_FUNCTION(address) (unsigned int)(((ulong)address & 0x0000fffff8000000)>>27)
	#define ZONE2M(address) (unsigned int) (((ulong)address & 0x0000ffffffe00000)>>21)
	#define MAX_NUM_THREAD_PER_ENTRY (64) //max number of trackable threads
	//more than 64 threads
		#define NGROUPS (((MAX_NUM_THREAD_PER_ENTRY) % 2)==0? (MAX_NUM_THREAD_PER_ENTRY >> 6) : ((MAX_NUM_THREAD_PER_ENTRY >> 6) +1))
		#define THREAD_GROUP(pgd_index) (pgd_index >> 6)
		#define THREAD_CELL(pgd_index) (pgd_index - (THREAD_GROUP(pgd_index)<< 6))
		#define SIZE_GROUP (64)
	//
 	#define NODE_GROUP(pde_relative) (pde_relative >> N_NODES_PER_BUCKET_LOG)
 	#define NODE_BIT(pde_relative) (pde_relative - (NODE_GROUP(pde_relative)<<N_NODES_PER_BUCKET_LOG))
 	#define CHECK_NODE(number_bit,node_tracking) (((1UL << ((ulong)number_bit & (BITS_PER_LONG -1))) & (node_tracking))>0?1:0)
	
	typedef struct __bucket_data{
		unsigned long nodes_tracking; //tracking 64 nodes of this bucket
		void * nodes_list;
		unsigned char spinlock; //CAS
	}bucket_data;
	
	#define SIZE_BUCKET_DATA (sizeof(bucket_data))
	
	typedef struct __header{
		void * next_node;
		unsigned int key_zone;
	}header;
	
	#define SIZE_HEADER (sizeof(header))
 	
 	#define ZONE_SINGLE_ACCESS
 	
 	#ifdef ZONE_SINGLE_ACCESS
 		
		typedef struct __body{
			unsigned long thread_tracking[NGROUPS];
		}body;
	
		#define SIZE_BODY (sizeof(body))
		
		#define update_body(pgd_index,a_node,pte_number) \
			do {\
				if(pgd_index>=MAX_NUM_THREAD_PER_ENTRY) {\
					printk("non trackable thread\n");\
					goto end_add_node;\
				}\
				else {\
					ulong * address_tracking = &((a_node->b).thread_tracking[THREAD_GROUP(pgd_index)]);\
					set_bit((ulong)THREAD_CELL(pgd_index),address_tracking);\
				}\
			}while(0)
			
		#define print_body(a_node) \
			do{\
				while(a_node!=NULL) {\
					unsigned char i;\
					for(i=0; i<NGROUPS; i++) {\
						unsigned long track = ((a_node->b).thread_tracking[i]);\
						printk("(a_node->h).key_zone=%d\n",(a_node->h).key_zone);\
						for(j=0; j<SIZE_GROUP; j++) {\
							unsigned int ctb = CHECK_NODE(j,track);\
							if(ctb)\
								printk("thread %d = %d\n",j,ctb);\
						}\
					}\
					a_node = (node *) ((a_node->h).next_node);\
				}\
			}while(0)
			
		#define printing_structs_info_aux() do{ }while(0)
		
		#define clean_body(a_node) do{}while(0)
		
 	#endif
 	
 	#ifdef ZONE_MULTI_ACCESS 
 		typedef unsigned char type_tracking;
 		/*#define MAX_TRACKING_DEBUG 255*/
 		typedef struct __body{
			type_tracking thread_tracking[NGROUPS][SIZE_GROUP];
		}body;
		
		#define SIZE_BODY (sizeof(body))
		
		#define update_body(pgd_index,a_node,pte_number) \
			do {\
				if(pgd_index>=MAX_NUM_THREAD_PER_ENTRY) {\
					printk("non trackable thread\n");\
					goto end_add_node;\
				}\
				else {\
					/*(a_node->b).thread_tracking[pgd_index]=MAX_TRACKING_DEBUG;\*/\
					(a_node->b).thread_tracking[THREAD_GROUP(pgd_index)][THREAD_CELL(pgd_index)]++;\
					if((((a_node->b).thread_tracking[THREAD_GROUP(pgd_index)][THREAD_CELL(pgd_index)])) == 0) {\
						(a_node->b).thread_tracking[THREAD_GROUP(pgd_index)][THREAD_CELL(pgd_index)]--;\
						printk("non trackable access\n");\
						goto end_add_node;\
					}\
				}\
			}while(0)
			
		#define print_body(a_node) \
			do{\
				while(a_node!=NULL) {\
					printk("(a_node->h).key_zone=%d\n",(a_node->h).key_zone);\
					unsigned int i;\
					for(i=0; i<NGROUPS; i++){\
						for(j=0; j<SIZE_GROUP; j++) {\
							type_tracking ctb = (a_node->b).thread_tracking[i][j];\
							if(ctb)\
								printk("thread %d = %d\n",j,ctb);\
						}\
					}\
					a_node = (node *) ((a_node->h).next_node);\
				}\
			}while(0)
		
		#define printing_structs_info_aux() do{ }while(0)
		
		#define clean_body(a_node) do{}while(0)
		
 	#endif
 	
 	#ifdef PAGE_SINGLE_ACCESS
 		typedef struct __body{
			void * pt;
		}body;
		
		#define SIZE_BODY (sizeof(body))
		
		typedef struct __page_node{
			unsigned short pte;
			void * next_page_node;
			unsigned long thread_tracking[NGROUPS];
		}page_node;
		
		#define SIZE_PAGE_NODE (sizeof(page_node))
		
		#define update_body(pgd_index,a_node,pte_number) \
			do{\
				if(pgd_index>=MAX_NUM_THREAD_PER_ENTRY) {\
					printk("non trackable thread\n");\
					goto end_add_node;\
				}\
				page_node * a_page_node = (a_node->b).pt;\
				page_node * new_page_node;\
				unsigned long * address_tracking;\
				if((a_page_node==NULL) || (pte_number < (a_page_node->pte))) {\
					printk("caso1\n");\
					a_page_node = kzalloc(SIZE_PAGE_NODE,GFP_KERNEL);\
					(a_page_node->pte)=pte_number;\
					(a_page_node->next_page_node)= ((a_node->b).pt);\
					((a_node->b).pt) = (void *) a_page_node;\
					finalize_update_node:	address_tracking = &(a_page_node->thread_tracking[THREAD_GROUP(pgd_index)]);\
					set_bit((unsigned long)THREAD_CELL(pgd_index),address_tracking);\
					goto end_add_node;\
				}\
				if((a_page_node->pte)==pte_number){\
					printk("caso2\n");\
					goto finalize_update_node;\
				}\
				else{\
					printk("caso3\n");\
					while((a_page_node->next_page_node)!=NULL){\
						if((((page_node *)(a_page_node->next_page_node))->pte)==pte_number)\
							goto case_equal;\
						if((((page_node *)(a_page_node->next_page_node))->pte)>pte_number)\
							goto case_smaller;\
						a_page_node=a_page_node->next_page_node;\
					}\
					printk("caso3.1_greater\n");\
					new_page_node = kzalloc(SIZE_PAGE_NODE,GFP_KERNEL);\
					(new_page_node->pte)=pte_number;\
					(a_page_node->next_page_node) = new_page_node;\
					a_page_node = new_page_node;\
					goto finalize_update_node;\
					\
					case_equal: printk("caso3.2_equal\n");\
					a_page_node = a_page_node -> next_page_node;\
					goto finalize_update_node;\
					\
					case_smaller: printk("caso3.3_smaller\n");\
					new_page_node = kzalloc(SIZE_PAGE_NODE,GFP_KERNEL);\
					(new_page_node->pte)=pte_number;\
					(new_page_node->next_page_node)=(a_page_node->next_page_node);\
					(a_page_node->next_page_node) = new_page_node;\
					a_page_node = new_page_node;\
					goto finalize_update_node;\
				}\
			}while(0)
		
		#define print_body(a_node) \
			do{\
				while(a_node!=NULL) {\
					printk("(a_node->h).key_zone=%d\n",(a_node->h).key_zone);\
					page_node * pt = (page_node *) (a_node->b).pt;\
					while(pt!=NULL) {\
						printk("(pt->pte)=%d\n",pt->pte);\
						unsigned int i;\
						for(i=0;i<NGROUPS;i++){\
							unsigned long track = (pt->thread_tracking[i]);\
							for(j=0; j<SIZE_GROUP; j++) {\
								unsigned int ctb = CHECK_NODE(j,track);\
								if(ctb)\
									printk("thread %d = %d\n",j,ctb);\
							}\
						}\
						pt=(page_node *) (pt->next_page_node);\
					}\
					a_node = (node *) ((a_node->h).next_node);\
				}\
			}while(0)
			
		#define printing_structs_info_aux() \
			do{\
				printk("SIZE_PAGE_NODE=%d\n",SIZE_PAGE_NODE);\
			}while(0)			
		
		#define clean_body(a_node) \
			do{\
				void * sublist = (a_node->b).pt;\
				void * sublist_aux = NULL;\
				unsigned int j;\
				while(sublist != NULL){\
					sublist_aux = ((page_node *)sublist)->next_page_node;\
					kfree(sublist);\
					sublist=sublist_aux;\
				}\
			}while(0)
	
 	#endif
 	
 	#ifdef PAGE_MULTI_ACCESS
 		typedef struct __body{
			void * pt;
		}body;
		
		#define SIZE_BODY (sizeof(body))
		
		typedef unsigned char type_tracking;
		
		/*#define MAX_TRACKING_DEBUG 255*/
		
		typedef struct __page_node{
			unsigned short pte;
			void * next_page_node;
			type_tracking thread_tracking[NGROUPS][SIZE_GROUP];
		}page_node;
		
		#define SIZE_PAGE_NODE (sizeof(page_node))
		
		#define update_body(pgd_index,a_node,pte_number) \
			do{\
				if(pgd_index>=MAX_NUM_THREAD_PER_ENTRY) {\
					printk("non trackable thread\n");\
					goto end_add_node;\
				}\
				page_node * a_page_node = (a_node->b).pt;\
				page_node * new_page_node;\
				if((a_page_node==NULL) || (pte_number < (a_page_node->pte))) {\
					printk("caso1\n");\
					a_page_node = kzalloc(SIZE_PAGE_NODE,GFP_KERNEL);\
					(a_page_node->pte)=pte_number;\
					(a_page_node->next_page_node)= ((a_node->b).pt);\
					((a_node->b).pt) = (void *) a_page_node;\
					finalize_update_node:/*(a_page_node->thread_tracking)[pgd_index] = MAX_TRACKING_DEBUG;*/\
					(a_page_node->thread_tracking)[THREAD_GROUP(pgd_index)][THREAD_CELL(pgd_index)]++;\
					if(((a_page_node->thread_tracking)[THREAD_GROUP(pgd_index)][THREAD_CELL(pgd_index)])==0) {\
						(a_page_node->thread_tracking)[THREAD_GROUP(pgd_index)][THREAD_CELL(pgd_index)]--;\
						printk("non trackable access\n");\
					}\
					goto end_add_node;\
				}\
				if((a_page_node->pte)==pte_number){\
					printk("caso2\n");\
					goto finalize_update_node;\
				}\
				else{\
					printk("caso3\n");\
					while((a_page_node->next_page_node)!=NULL){\
						if((((page_node *)(a_page_node->next_page_node))->pte)==pte_number)\
							goto case_equal;\
						if((((page_node *)(a_page_node->next_page_node))->pte)>pte_number)\
							goto case_smaller;\
						a_page_node=a_page_node->next_page_node;\
					}\
					printk("caso3.1_greater\n");\
					new_page_node = kzalloc(SIZE_PAGE_NODE,GFP_KERNEL);\
					(new_page_node->pte)=pte_number;\
					(a_page_node->next_page_node) = new_page_node;\
					a_page_node = new_page_node;\
					goto finalize_update_node;\
					\
					case_equal: printk("caso3.2_equal\n");\
					a_page_node = a_page_node -> next_page_node;\
					goto finalize_update_node;\
					\
					case_smaller: printk("caso3.3_smaller\n");\
					new_page_node = kzalloc(SIZE_PAGE_NODE,GFP_KERNEL);\
					(new_page_node->pte)=pte_number;\
					(new_page_node->next_page_node)=(a_page_node->next_page_node);\
					(a_page_node->next_page_node) = new_page_node;\
					a_page_node = new_page_node;\
					goto finalize_update_node;\
				}\
			}while(0)
			
		#define print_body(a_node) \
			do{\
				while(a_node!=NULL) {\
					printk("(a_node->h).key_zone=%d\n",(a_node->h).key_zone);\
					page_node * pt = (page_node *) (a_node->b).pt;\
					while(pt!=NULL) {\
						printk("(pt->pte)=%d\n",pt->pte);\
						unsigned int i;\
						for(i=0;i<NGROUPS;i++){\
							for(j=0; j<SIZE_GROUP; j++) {\
								type_tracking ctb = (pt->thread_tracking)[i][j];\
								if(ctb)\
									printk("thread %d = %d\n",j,ctb);\
							}\
						}\
						pt=(page_node *) (pt->next_page_node);\
					}\
					a_node = (node *) ((a_node->h).next_node);\
				}\
			}while(0)
			
		#define printing_structs_info_aux() \
			do{\
				printk("SIZE_PAGE_NODE=%d\n",SIZE_PAGE_NODE);\
			}while(0)
		
		#define clean_body(a_node) \
			do{\
				void * sublist = (a_node->b).pt;\
				void * sublist_aux = NULL;\
				unsigned int j;\
				while(sublist != NULL){\
					sublist_aux = ((page_node *)sublist)->next_page_node;\
					kfree(sublist);\
					sublist=sublist_aux;\
				}\
			}while(0)
			
 	#endif
 	
 	typedef struct __node{
			header h;
			body b;
	}node;
	
	#define SIZE_NODE (sizeof(node))
 	
 	void update_hashbucket(void *,unsigned char);
 	void audit_hashbucket(void);
 	void clean_hashbucket(void);
 	//debug functions
 	void printing_structs_info(void);
 	void worst_case_zone(void);
 	void worst_case_page(void);
 	//


 #endif 
