/*                       Copyright (C) 2008-2013 HPDCS Group
*                       http://www.dis.uniroma1.it/~hpdcs
*
*
* This file is part of ROOT-Sim (ROme OpTimistic Simulator).
* 
* ROOT-Sim is free software; you can redistribute it and/or modify it under the
* terms of the GNU General Public License as published by the Free Software
* Foundation; either version 3 of the License, or (at your option) any later
* version.
* 
* ROOT-Sim is distributed in the hope that it will be useful, but WITHOUT ANY
* WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
* A PARTICULAR PURPOSE. See the GNU General Public License for more details.
* 
* You should have received a copy of the GNU General Public License along with
* ROOT-Sim; if not, write to the Free Software Foundation, Inc.,
* 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
* 
* @file ktblmgr.c 
* @brief This is the main source for the Linux Kernel Module which implements
*	per-kernel-thread different page table for supporting shared state.
* @author Alessandro Pellegrini
* @author Francesco Quaglia
*
* @date November 15, 2013
*/

#define HAVE_LINUX_KERNEL_MAP_MODULE

#ifdef HAVE_LINUX_KERNEL_MAP_MODULE

#define EXPORT_SYMTAB
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/errno.h>
#include <linux/device.h>
#include <linux/kprobes.h>
#include <linux/mutex.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/version.h>
#include <asm/tlbflush.h>
#include <asm/page.h>
#include <asm/cacheflush.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>



#include "ktblmgr.h"

#define AUXILIARY_FRAMES 256

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,25)
#error Unsupported Kernel Version
#endif

/* FUNCTION PROTOTYPES */
static int rs_ktblmgr_init(void);
static void rs_ktblmgr_cleanup(void);
static int rs_ktblmgr_open(struct inode *, struct file *);
static int rs_ktblmgr_release(struct inode *, struct file *);
static long rs_ktblmgr_ioctl(struct file *, unsigned int, unsigned long);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Alessandro Pellegrini <pellegrini@dis.uniroma1.it>, Francesco Quaglia <quaglia@dis.uniroma1.it>");
MODULE_DESCRIPTION("ROOT-Sim Multiple Page Table Kernel Module");
module_init(rs_ktblmgr_init);
module_exit(rs_ktblmgr_cleanup);

/* MODULE VARIABLES */

extern (*rootsim_pager)(struct task_struct *tsk); 
extern void rootsim_load_cr3(ulong addr); 

/// Device major number
static int major;

/// Only one process can access this device (before spawning threads!)
static DEFINE_MUTEX(rs_ktblmgr_mutex);

struct mutex pgd_get_mutex;
struct mm_struct *mm_struct_addr[SIBLING_PGD];
void *pgd_addr[SIBLING_PGD];
unsigned int managed_pgds = 0;
struct mm_struct *original_view[SIBLING_PGD];

/* stack of auxiliary frames - used for chnage view */
//int stack_index = AUXILIARY_FRAMES - 1;
//void * auxiliary_frames[AUXILIARY_FRAMES];

int root_sim_processes[SIBLING_PGD]={[0 ... (SIBLING_PGD-1)] = -1};

//#define MAX_CROSS_STATE_DEPENDENCIES 1024
//int currently_open[SIBLING_PGD][MAX_CROSS_STATE_DEPENDENCIES]; 
//int open_index[SIBLING_PGD]={[0 ... (SIBLING_PGD-1)] = -1};

void**ancestor_pml4;
int restore_pml4;  /* starting entry of pml4 for release operations of shadow pdp tables */
int restore_pml4_entries; /* entries of the pml4 involvrd in release operations of shadow pdp tables */
int mapped_processes; /* number of processes (application objects) mapped onto the special segment */

ulong callback;

struct vm_area_struct* changed_mode_mmap;
struct vm_operations_struct * original_vm_ops;
struct vm_operations_struct auxiliary_vm_ops_table;
struct vm_area_struct *target_vma;

// Specify sys device attributes

int (*original_fault_handler)(struct vm_area_struct *vma, struct vm_fault *vmf);

static DEVICE_ATTR(multimap, S_IRUSR|S_IRGRP|S_IROTH, NULL, NULL);

/// File operations for the module
struct file_operations fops = {
	open:	rs_ktblmgr_open,
	unlocked_ioctl:rs_ktblmgr_ioctl,
	compat_ioctl:rs_ktblmgr_ioctl,// Nothing strange is passed, so 32 bits programs should work out of the box
	//release:rs_ktblmgr_release
};

/// This is to access the actual flush_tlb_all using a kernel proble
void (*flush_tlb_all_lookup)(void) = NULL;

#define ACCESSES_HASHBUCKET
/* Tabella Hash con trabocco, ogni entry della tabella punta ad una lista di 64 nodi, ogni nodo rappresenta una pde.
 * In testa ad ogni lista c'è un ulteriore nodo, che punta al primo vero nodo della lista e tiene traccia dei 64
 * nodi presenti nella lista. L'inserimento costa O(1) sia nel caso di lista vuota che non perchè, grazie al nodo
 * "di controllo", viene fatto sempre in testa. Nel caso di nodo già presente, l'aggiornamento del nodo costa al
 * più O(64) per lo scorrimento. Per ogni lista di nodi c'è un semaforo di mutua esclusione realizzato con la
 * Compare-and-Swap (CAS) al byte. Realizzato solo l'inserimento dei nodi nelle varie liste e l'aggiornamento.
 * Non realizzata l'eliminazione.  */
#ifdef ACCESSES_HASHBUCKET
	
	#define NZONE2M (71303168)
	#define NBUCKETS (1114112)
	#define N_NODES_PER_BUCKET (64)
	#define N_NODES_PER_BUCKET_LOG (6)
	#define HASH_FUNCTION(address) (unsigned int)(((ulong)address & 0x0000fffff8000000)>>27)
	#define ZONE2M(address) (unsigned int) (((ulong)address & 0x0000ffffffe00000)>>21)
	
	typedef struct{
		unsigned int key_zone;
		void * next_node;
	}header;
	
	typedef struct{
		unsigned long node_tracking;
		void * first_real_node;
	}control_node;
	
	#define SIZE_HEADER (sizeof(header))
	#define SIZE_CONTROL_NODE (sizeof(control_node))
	#define SIZE_PAGE_4K (4096)
	#define NPTE (512)
	#define MAX_SIZE_BODY_ENTRY ((SIZE_PAGE_4K - SIZE_HEADER)>>9)
    /*#define M8 (MAX_SIZE_BODY_ENTRY==8?8:0)
    #define M4 ((MAX_SIZE_BODY_ENTRY>=4 && MAX_SIZE_BODY_ENTRY<8)?4:0)
    #define M2 ((MAX_SIZE_BODY_ENTRY>=2 && MAX_SIZE_BODY_ENTRY<4)?2:0)
    #define M1 ((MAX_SIZE_BODY_ENTRY>=1 && MAX_SIZE_BODY_ENTRY<2)?1:0)
    #define M (M8+M4+M2+M1)*/
    #define MAX_SIZE_BODY_ENTRY_REAL ((MAX_SIZE_BODY_ENTRY==8?8:0)+((MAX_SIZE_BODY_ENTRY>=4 && MAX_SIZE_BODY_ENTRY<8)?4:0)+((MAX_SIZE_BODY_ENTRY>=2 && MAX_SIZE_BODY_ENTRY<4)?2:0)+((MAX_SIZE_BODY_ENTRY>=1 && MAX_SIZE_BODY_ENTRY<2)?1:0))
 	#define MAX_NUM_THREAD_PER_ENTRY (MAX_SIZE_BODY_ENTRY_REAL * 8)
 	#define WASTE_BITS (64-MAX_NUM_THREAD_PER_ENTRY)
 	#define NODE_GROUP(pde_relative) (pde_relative >> N_NODES_PER_BUCKET_LOG)
 	#define NODE_BIT(pde_relative) (pde_relative - (NODE_GROUP(pde_relative)<<N_NODES_PER_BUCKET_LOG))
 	#define CHECK_NODE(number_bit,node_tracking) (((1UL << ((ulong)number_bit & (BITS_PER_LONG -1))) & (node_tracking))>0?1:0)
 	
	typedef struct{
		unsigned char page_table[MAX_SIZE_BODY_ENTRY_REAL * NPTE];
	}body;
	
	typedef struct{
		header h;
		body b;
	}node;
	
	#define SIZE_NODE (sizeof(node))
	
	void * buckets[NBUCKETS];
	//spinlock_t spinlocks[NBUCKETS] = {[0 ... (NBUCKETS-1)]=SPIN_LOCK_UNLOCKED};
	unsigned char exclusion[NBUCKETS] = {[0 ... (NBUCKETS-1)]=0};
	//struct mutex hash_mutex;
	
	void add_node(void * fault_address,unsigned char pgd_index){
		
			
		unsigned int bucket_index = HASH_FUNCTION(fault_address);
		//spin_lock(&(spinlocks[bucket_index]));
		while(cmpxchg(&(exclusion[bucket_index]),0,1)); //while(lock==1)==while(locked)
		printk("bucket_index=%d\n",bucket_index);
		printk("key_zone=%d\n",ZONE2M(fault_address));
		printk("pte=%d\n",PTE(fault_address));
		printk("pde_relative=%d\n",PDE(fault_address));
		control_node * head;
		node * a_node;
		if(buckets[bucket_index]==NULL) {
			head = kzalloc(SIZE_CONTROL_NODE,GFP_KERNEL);
			a_node=kzalloc(SIZE_NODE,GFP_KERNEL);
			(a_node -> h).key_zone = ZONE2M(fault_address);
			head->first_real_node=(void *) a_node;
			set_bit(NODE_BIT(PDE(fault_address)),&(head->node_tracking));
			//unsigned int tb = test_bit(NODE_BIT(PDE(fault_address)),&(head->node_tracking));
			//printk("tb=%u\n",tb);
			buckets[bucket_index]=head;
			goto update_body;
		}
		else {
			head = buckets[bucket_index];
			//if(!constant_test_bit(NODE_BIT(PDE(fault_address)),&(head->node_tracking))) {
			if(!CHECK_NODE(NODE_BIT(PDE(fault_address)),head->node_tracking)) {
				node * new_node = kzalloc(SIZE_NODE,GFP_KERNEL);
				(new_node->h).key_zone=ZONE2M(fault_address);
				(new_node->h).next_node = head->first_real_node;
				head->first_real_node=new_node;
				set_bit(NODE_BIT(PDE(fault_address)),&(head->node_tracking));
				a_node = new_node;
				goto update_body;
			}
			else {
				a_node = head->first_real_node;
				while((a_node->h).next_node!=NULL) {
					if((a_node->h).key_zone == ZONE2M(fault_address))
						goto update_body;
					a_node = (node *) ((a_node->h).next_node);
				}
				if((a_node->h).key_zone==ZONE2M(fault_address))
					goto update_body;
			}
		}
		
		update_body: 
		if(pgd_index>=MAX_NUM_THREAD_PER_ENTRY)
			goto end_add_node;
		else {
			unsigned char * pt = (unsigned char *)((a_node->b).page_table);
			printk("pt=%p\n",pt);
			unsigned char * pte = &(pt[MAX_SIZE_BODY_ENTRY_REAL*PTE(fault_address)]);
			ulong * pte_long = (ulong *) pte;
			printk("pte_long=%p,*pte_long=%u, sizeof(*pte_long)=%d\n",pte_long,*pte_long,sizeof(*pte_long));
			//printk("WASTE_BITS=%d\n",WASTE_BITS);
			set_bit((ulong)(pgd_index+WASTE_BITS),pte_long);
		}
		//end_add_node: spin_unlock(&(spinlocks[bucket_index]));
		end_add_node: cmpxchg(&(exclusion[bucket_index]),1,0); //unlocked
		return;	
	}
	
#endif

int root_sim_page_fault(struct pt_regs* regs, long error_code){
 	void* target_address;
	void ** my_pgd;
	void ** my_pdp;
	void** ancestor_pdp;
	ulong i;
    void ** my_pd;
    void ** ancestor_pd;
    void * address;
    
	if(current->mm == NULL) return 0;  /* this is a kernel thread - not a rootsim thread */
                                           /* i kernel thread hanno current->mm=NULL di regola */
	target_address = (void*)read_cr2(); 

	/* discriminate whether this is a classical fault or a root-sim proper fault */       
    //printk("ancestor_pml4=%p\n",ancestor_pml4);
	for(i=0;i<SIBLING_PGD;i++){
		if ((root_sim_processes[i])==(current->pid)){	
                        
                        printk("process found\n");
                        printk("current->mm->pgd=%p,,,pgd_addr[%d]=%p,,,cr3=%p\n",current->mm->pgd,i,pgd_addr[i],__va(read_cr3()));
                        printk("page-fault address=%p\n",target_address);
                        printk("ancestor_pml4=%p\n",ancestor_pml4);
			my_pgd =(void**) pgd_addr[i];
			if(ancestor_pml4[PML4(target_address)] != NULL && ((ulong)ancestor_pml4[PML4(target_address)] & 0x4)==0x4) {
				printk("ancestor_pml4[%d]!=NULL\n",PML4(target_address));
				if(my_pgd[PML4(target_address)]!=NULL) {
					printk("my_pgd[%d]!=NULL\n",PML4(target_address));
					ancestor_pdp = (void **) __va((ulong)ancestor_pml4[PML4(target_address)] & 0xfffffffffffff000);
					if(ancestor_pdp[PDP(target_address)]!=NULL){
						printk("ancestor_pdp[%d]!=NULL\n",PDP(target_address));
			 			my_pdp = (void **)__va((ulong) my_pgd[PML4(target_address)] & 0xfffffffffffff000);
			 			if(my_pdp[PDP(target_address)]!=NULL){
			 				printk("my_pdp[%d]!=NULL\n",PDP(target_address));
			 				ancestor_pd= (void**) __va((ulong)ancestor_pdp[PDP(target_address)] & 0xfffffffffffff000);
			 				if(ancestor_pd[PDE(target_address)]!=NULL) {
			 					printk("ancestor_pd[%d]!=NULL\n",PDE(target_address));
			 					my_pd = (void **)__va((ulong) my_pdp[PDP(target_address)] & 0xfffffffffffff000);
			 					if(my_pd[PDE(target_address)]!=NULL){
			 						printk("my_pd[%d]!=NULL\n",PDE(target_address));
			 						#ifdef ACCESSES_HASHBUCKET
			 							add_node(target_address,i);
			 						#endif
			 						return 0;
								}
			 					else {
			 						printk("my_pd[%d]=NULL\n",PDE(target_address));
			 						my_pd[PDE(target_address)]=(ulong)ancestor_pd[PDE(target_address)];
			 						#ifdef ACCESSES_HASHBUCKET
			 							add_node(target_address,i);
			 						#endif
			 						return 1;
			 					}
			 				}
			 				else {
			 					printk("ancestor_pd[%d]=NULL\n",PDE(target_address));
			 					#ifdef ACCESSES_HASHBUCKET
			 						add_node(target_address,i);
			 					#endif
			 					return 0;
							}
			   			}
			   				
			   			else {
			   				printk("my_pdp[%d]=NULL\n",PDP(target_address));
							address = get_zeroed_page(GFP_KERNEL);
							address = __pa(address);
							address = (ulong)address | ((ulong)ancestor_pdp[PDP(target_address)] & 0x0000000000000fff);
							my_pdp[PDP(target_address)]=address;
							return 0;
						}
					}
					else {
						printk("ancestor_pdp[%d]=NULL\n",PDP(target_address));
						return 0;
					}
				}
				else {
					printk("my_pgd[%d]=NULL\n",PML4(target_address));
					address = get_zeroed_page(GFP_KERNEL);
					address = __pa(address);
					address = (ulong)address | ((ulong)ancestor_pml4[PML4(target_address)] & 0x0000000000000fff);
					my_pgd[PML4(target_address)]=address;
					return 0;
				}
		    }
		    else {
		    	printk("ancestor_pml4[%d]=%p\n",PML4(target_address),ancestor_pml4[PML4(target_address)]);
		    	return 0;
			}
                        
		}/*end if*/ 
	}/*end for*/
	
	return 0;
}

EXPORT_SYMBOL(root_sim_page_fault);

int rs_ktblmgr_open(struct inode *inode, struct file *filp) {

	// It's meaningless to open this device in write mode
	if (((filp->f_flags & O_ACCMODE) == O_WRONLY)
	    || ((filp->f_flags & O_ACCMODE) == O_RDWR)) {
		return -EACCES;
	}

	return 0;

//skip blocking
	// Only one access at a time
	if (!mutex_trylock(&rs_ktblmgr_mutex)) {
		return -EBUSY;
	}

	return 0;
}


int rs_ktblmgr_release(struct inode *inode, struct file *filp) {
    int i,j,k;
	//int pml4;
	//int involved_pml4;
	void** pgd_entry;
	//void** temp;
	//void* address;
    void ** my_pdp;
    void ** my_pd;
	// already logged by ancestor set 
	//pml4 = restore_pml4; 
	//involved_pml4 = restore_pml4_entries;

	for (j=0;j<SIBLING_PGD;j++){
		if(original_view[j]!=NULL){ // need to recover memory used for PDPs that have not been deallocated                         

			pgd_entry = (void**)pgd_addr[j];

			for (i=0; i<512; i++){
			
				if(pgd_entry[i]!=NULL){   
					if(((ulong)pgd_entry[i] & 0x4)==0x4){       
            			my_pdp = (void **)(__va((unsigned long)pgd_entry[i] & 0xfffffffffffff000));
                		for(k=0; k<512; k++) {
                   			if(my_pdp[k] != NULL) {
                       			my_pd = (void **)__va((unsigned long)my_pdp[k]&0xfffffffffffff000);
        	                	free_pages((unsigned long)(my_pd),0);
							}
                		}
                		free_pages((unsigned long)my_pdp,0);
            		}
            		else {
            			//printk("kernel's PML4E:%d, no release\n",i);
		 				break;
		 			}
		 		}
		 	
			}// end for i
			original_view[j]=NULL;
            //pml4=restore_pml4;
		}// enf if != NULL
	}// end for j

	return 0;
}


static void print_bits(unsigned long long number) {
	unsigned long long mask = 0x8000000000000000; // 64 bit
	char digit;

	while(mask) {
		digit = ((mask & number) ? '1' : '0');
		mask >>= 1 ;
	}
}


static long rs_ktblmgr_ioctl(struct file *filp, unsigned int cmd, unsigned long arg) {

	int ret = 0;
	int i,j,k,z;
	void ** my_pdp;
	void** ancestor_pdp;
	void* cr3;
	void** pgd_entry;
	void* pdp_entry;
	void* pde_entry;
	void* pte_entry;
	void** temp;
	void** temp1;
	void** temp2;
	int descriptor;
	struct vm_area_struct *mmap;
	void* address;
	int pml4;
	int involved_pml4;
    void*control_bits;
    void ** my_pd;
    unsigned char cell;
    unsigned int pd_entry;
    unsigned int zone_num_calc;
    void ** ancestor_pd;
    
	switch (cmd) {

	case IOCTL_INIT_PGD:
		break;

	case IOCTL_REGISTER_THREAD:
		root_sim_processes[arg] = current->pid;
        //printk("root_sim_processes[%d]=%d\n",arg,root_sim_processes[arg]);
		break;

	case IOCTL_DEREGISTER_THREAD:
		root_sim_processes[arg] = -1;
		break;

	case IOCTL_SET_ANCESTOR_PGD:
		ancestor_pml4 = (void**)current->mm->pgd;
		printk("ancestor_pml4=%p\n",ancestor_pml4);
		break;

	case IOCTL_GET_PGD:/*thread piattaforma*/
		printk("getting pgd\n");
		mutex_lock(&pgd_get_mutex);
		for (i = 0; i < SIBLING_PGD; i++) {
			if (original_view[i] == NULL) {
				memcpy((void *)pgd_addr[i], (void *)(current->mm->pgd), 4096); /* copia della pgd originale per non avere subito dei page fault */
				original_view[i] = current->mm;
				descriptor = i;
				ret = descriptor;
				goto pgd_get_done;
	 		}/*end if*/
		}/*end for*/
		ret = -1;
		pgd_get_done:
		mutex_unlock(&pgd_get_mutex);
		arg = ret; 
    	printk("changing view\n");
		flush_cache_all();
		
		if(arg>=0){
					pgd_entry = (void**)pgd_addr[arg];    
					for (i=0; i<512; i++){ 
        				if(ancestor_pml4[i] != NULL){
        					if(((ulong)ancestor_pml4[i] & 0x4)==0x4) {
            					control_bits = (ulong)ancestor_pml4[i] & 0x0000000000000fff;
                				address=(void *)get_zeroed_page(GFP_KERNEL);
                				address = __pa((ulong)address);
                				address = (ulong) address | (ulong) control_bits;
                				pgd_entry[i]=address; 
 
                				my_pdp = (void**)(__va((ulong)pgd_entry[i] & 0xfffffffffffff000));
                				ancestor_pdp =(void **) __va((ulong) ancestor_pml4[i] & 0xfffffffffffff000);
                            
                				for(j=0; j<512; j++) { 
                					if(ancestor_pdp[j] != NULL) {
                    					control_bits = (ulong) ancestor_pdp[j] & 0x0000000000000fff;
                                 
                        				address=get_zeroed_page(GFP_KERNEL);
                        				address=__pa((ulong)address);
                        				address = (ulong) address | (ulong) control_bits;
                        				my_pdp[j]=address;
                    				}
                				}
            				}
            				else {
								//printk("kernel's PML4E=%d\n",i);
								break;
							}
						}
        			}
       			printk("pgd_addr[%d]=%p\n",arg,pgd_addr[arg]);       	
        		
		}
        
		break;

	case IOCTL_RELEASE_PGD:
		printk("restoring the view\n");
		if(original_view[arg]!=NULL) {	
			pgd_entry = (void**)pgd_addr[arg];

			for (i=0; i<512; i++){
			
				if(pgd_entry[i]!=NULL){   
					if(((ulong)pgd_entry[i] & 0x4)==0x4){       
            			my_pdp = (void **)(__va((unsigned long)pgd_entry[i] & 0xfffffffffffff000));
                		for(j=0; j<512; j++) {
                   			if(my_pdp[j] != NULL) {
                       			my_pd = (void **)__va((unsigned long)my_pdp[j]&0xfffffffffffff000);
        	                	free_pages((unsigned long)(my_pd),0);
							}
                		}
                		free_pages((unsigned long)my_pdp,0);
            		}
            		else {
            			//printk("kernel's PML4E:%d, no release\n",i);
		 				break;
		 			}
		 		}
			}
			
			original_view[arg]=NULL;
		}
		printk("all things released\n");

        printk("current->mm->pgd=%p,pgd_addr[%d]=%p\n",current->mm->pgd,arg,pgd_addr[arg]);
		printk("cr3=%p\n",__va(read_cr3()));
		/*if (original_view[arg] != NULL) {
			original_view[arg] = NULL;
			ret = 0;
			break;
		}
		else{

		}*/
		ret=0;

		break;

	case IOCTL_INSTALL_PGD:	
		if (original_view[arg] != NULL) {
			//debug code
				printk("original_view[%d]->pgd=%p\n",arg,original_view[arg]->pgd);
				printk("ancestor_pml4=%p\n",ancestor_pml4);
				printk("current->mm->pgd=%p\n",current->mm->pgd);
			//end debug code
			root_sim_processes[arg] = current->pid;
            rootsim_load_cr3(pgd_addr[arg]);
            ret = 0;
            printk("successfully installed\n");
			break;
		}
		else{
		 	printk("bad pgd install\n");
		 	break;
		}

	case IOCTL_GET_INFO_PGD:
	   
		printk("printing info\n");
        //printk("pgd_addr[%d]=%p\n",arg,pgd_addr[arg]);
        //pgd_entry = (void **) pgd_addr[arg];
        
        /*for(i=0; i<512; i++) {
        	if(ancestor_pml4[i]!=NULL){
            	printk("ancestor_pml4[%d]=%p\n",i,ancestor_pml4[i]);
                if(((ulong)ancestor_pml4[i] & 0x0000000000000001)==0x0000000000000001){
                	ancestor_pdp = (void**) __va((ulong) ancestor_pml4[i] & 0xfffffffffffff000);
                	for(j=0; j<512; j++){
                		if(ancestor_pdp[j]!=NULL) {
                			printk("ancestor_pdp[%d]=%p\n",j,ancestor_pdp[j]);
                			ancestor_pd = (void**) __va((ulong)ancestor_pdp[j] & 0xfffffffffffff000);
                			for(k=0;k<512;k++){
								if(ancestor_pd[k]!=NULL) {
									printk("ancestor_pd[%d]=%p\n",k,ancestor_pd[k]);
									//ancestor_pt = (void**)__va((ulong) ancestor_pd[k] & 0xfffffffffffff000);
									//for(h=0;h<512;h++){
									//	if(ancestor_pt[h]!=NULL)
									//		printk("ancestor_pt[%d]=%p\n",h,ancestor_pt[h]);
									//}
								}
							}
                		}	
                	}
				}
			}
		}*/
		//break;
				
		/*for(i=0; i<512; i++) {
        	if(pgd_entry[i]!=NULL){
            	//printk("pgd_entry[%d]=%p\n",i,pgd_entry[i]);
                if(((ulong)pgd_entry[i] & 0x4)==0x4){
                	my_pdp = (void**) __va((ulong) pgd_entry[i] & 0xfffffffffffff000);
                	for(j=0; j<512; j++){
                		if(my_pdp[j]!=NULL) {
                			//printk("my_pdp[%d]=%p\n",j,my_pdp[j]);
                			my_pd = (void **) __va((ulong) my_pdp[j] & 0xfffffffffffff000);
                			for(k=0;k<512;k++){
								if(my_pd[k]!=NULL) {
									printk("my_pd[%d]=%p\n",k,my_pd[k]);
									if(((ulong)my_pd[k] & 0x080)==0x000){ //4Kbyte page
										my_pt = (void**) __va((ulong)my_pd[k] & 0xfffffffffffff000);
										for(h=0;h<512;h++){
											if(my_pt[h]!=NULL)
												printk("my_pt[%d]=%p\n",h,my_pt[h]);
										}
									}
								}
							}
                		}	
                	}	
                }
                else break;
			}
		}*/
		
        for(i=0;i<SIBLING_PGD;i++) {
        	if(original_view[i]!=NULL) 
        		printk("original_view[%d]=%p\n",i,original_view[i]);
        	printk("root_sim_processes[%d]=%d\n",i,root_sim_processes[i]);	
        }
        
        /*for(i=0;i<272;i++) {
        	for(j=0; j<512; j++) {
        		for(k=0; k<512; k++) {
        			pd_entry = k >> 6;
        			zone_num_calc = j << 3;
        			pd_entry |= zone_num_calc;
        			zone_num_calc = i << 12;
        			pd_entry |= zone_num_calc;
        			printk("entry=%d\n",pd_entry);
				}
			}
		}*/ 
		
		#ifdef ACCESSES_HASHBUCKET
			for(i=0; i<NBUCKETS; i++) {
				if(buckets[i]!=NULL){
					control_node * head = buckets[i];
					printk("head n° %d=%u\n",i,head->node_tracking);
					for(k=0;k<64;k++) {
						//unsigned int ctb = constant_test_bit(k,&(head->node_tracking));
						unsigned int ctb = CHECK_NODE(k,head->node_tracking);
						if(ctb)
							printk("bit %d = %d\n",k,ctb);
						
					}
					node * a_node = (node*)head->first_real_node;
					//printk("bucket n°=%d\n",i);
					while(a_node!=NULL) {
						printk("(a_node->h).key_zone=%d\n",(a_node->h).key_zone);
						unsigned char * pt = (a_node->b).page_table;
						for(j=0; j<NPTE; j++) {
							unsigned long * pte = (ulong *)&(pt[(MAX_SIZE_BODY_ENTRY_REAL*j)/*+MAX_SIZE_BODY_ENTRY_REAL*/]);
							unsigned long pte_l = *pte;
							//*pte_n = *pte_n << WASTE_BITS;
							pte_l = pte_l >> WASTE_BITS;
							if(pte_l>0)
								printk("pt[%d]=%u\n",j,pte_l);
							//pt+=MAX_SIZE_BODY_ENTRY_REAL;
						}
						a_node = (node *) ((a_node->h).next_node);
					}
				}	
			}
		#endif
		
		/*unsigned char prova[8] = {1,1,1,1,1,1,1,1};
		unsigned long * l = prova;
		printk("*l=%ul\n",*l);
		unsigned int * in = prova;
		printk("*in=%u\n",*in);
		in++;
		printk("*in=%u\n",*in);
		unsigned short * sh = prova;
		printk("*sh=%u\n",*sh);
		sh++;
		printk("*sh=%u\n",*sh);
		sh++;
		printk("*sh=%u\n",*sh);
		sh++;
		printk("*sh=%u\n",*sh);
		unsigned char * c = prova;
		printk("*c=%u\n",*c);
		c++;
		printk("*c=%u\n",*c);
		c++;
		printk("*c=%u\n",*c);
		c++;
		printk("*c=%u\n",*c);
		c++;
		printk("*c=%u\n",*c);
		c++;
		printk("*c=%u\n",*c);
		c++;
		printk("*c=%u\n",*c);
		c++;
		printk("*c=%u\n",*c);*/
		
        
        break;

	case IOCTL_GET_INFO_VMAREA:
		mmap = current->mm->mmap;
		int count; 
		unsigned long vmarea_address;
		int howmany;
        
		for(i=0;mmap;i++){
			count=(mmap->vm_end)-(mmap->vm_start);
			vmarea_address=mmap->vm_start;
			for(j=0;j<count;j++){
				//if(vmarea_address==0x0000000001804000) printk("found\n");
				printk("vm area address n°%d di area %d =%p\n",j,i,vmarea_address);
				vmarea_address++;
				howmany++;
			}
			mmap = mmap->vm_next;
		}	
        printk("total number of vm areas=%d\n",howmany);
        
        /*mmap = current->mm->mmap_cache;
		count=0;
		
		howmany=0;
        
		for(i=0;mmap;i++){
			count=(mmap->vm_end)-(mmap->vm_start);
			vmarea_address=mmap->vm_start;
			for(j=0;j<count;j++){
				printk("vm area address n°%d di area %d =%p\n",j,i,vmarea_address);
				vmarea_address++;
				howmany++;
			}
			mmap = mmap->vm_next;
		}	
        printk("number of last used vm areas=%d\n",howmany);*/
        
		break;

	case IOCTL_GET_CR_REGISTERS:/* registri memorizzati in una variabile */
		asm volatile("movq %%CR0, %0":"=r" (cr3));
		print_bits((unsigned long long)cr3);
		
		asm volatile("\nmovq %%CR2, %0":"=r" (cr3));
		print_bits((unsigned long long)cr3);
		
		asm volatile("\nmovq %%CR3, %0":"=r" (cr3));
		print_bits((unsigned long long)cr3);
		
		asm volatile("\nmovq %%CR4, %0":"=r" (cr3));
		print_bits((unsigned long long)cr3);

		break;

	case IOCTL_UNINSTALL_PGD:
                
		if(current->mm != NULL){
			root_sim_processes[arg] = -1;
			rootsim_load_cr3(current->mm->pgd);
			printk("successfully uninstalled\n");
		}
			ret = 0;	
			break;

	case IOCTL_SET_VM_RANGE:

			flush_cache_all(); /* to make new range visible across multiple runs */
			
			mapped_processes = (((ioctl_info*)arg)->mapped_processes);
			involved_pml4 = (((ioctl_info*)arg)->mapped_processes) >> 9; 
			if ( (unsigned)((ioctl_info*)arg)->mapped_processes & 0x00000000000001ff ) involved_pml4++;

			callback = ((ioctl_info*)arg)->callback;


			pml4 = (int)PML4(((ioctl_info*)arg)->addr);

			restore_pml4 = pml4;
			restore_pml4_entries = involved_pml4;


			flush_cache_all(); /* to make new range visible across multiple runs */

		break;

	case IOCTL_TRACE_VMAREA:
			
		mmap = current->mm->mmap;
		for(i=0;mmap && (i<128);i++){
			if (((void*)arg >= (void*)mmap->vm_start) && ((void*)(arg)<=(void*)mmap->vm_end)){
				goto secondlevel;
			}	
			mmap = mmap->vm_next;
		}	
		if(!mmap){
			break;
		}
		secondlevel:
		pgd_entry = (void*)current->mm->pgd;	
		address = (void*)mmap->vm_start;
		for ( ; PML4(address) <= PML4((void*)mmap->vm_end) ; ){
			pdp_entry = (void*)pgd_entry[(int)PML4(address)];
			pdp_entry = (void*)((ulong) pdp_entry & 0xfffffffffffff000);
			if(pdp_entry != NULL){
				pdp_entry = __va(pdp_entry);		
				temp = (void*)pdp_entry;	
				for(i=0;i<512;i++){				
					if ((temp[i]) != NULL){
					//internal loop om PDE entries
					}
				}	
			}
			address = PML4_PLUS_ONE(address);
		}
		break;

		for ( ; PML4(address) <= PML4((void*)mmap->vm_end) ; ){
			pdp_entry = (void*)pgd_entry[(int)PML4(address)];
			pdp_entry = (void*)((ulong) pdp_entry & 0xfffffffffffff000);
			pdp_entry = __va(pdp_entry);		
			temp = (void**)pdp_entry;	
			for(i=0;i<512;i++){			
				if ((temp[i]) != NULL){
					//internal loop om PDE entries				
					pde_entry = (void*)((ulong) temp[i] & 0xfffffffffffff000);  					
					pde_entry = __va(pde_entry);
					temp1 = (void**)pde_entry;
					for(j=0;j<512;j++){
						if ((temp1[j]) != NULL){
						//now tracing the PTE						
							pte_entry = (void*)((ulong) temp1[j] & 0xfffffffffffff000);  
							pte_entry = __va(pte_entry);
							temp2 = (void**)pte_entry;
							for(z=0;z<512;z++){
								if ((temp2[z]) != NULL){
								} // end if temp2
							}// end for z
				   		}// end if temp1
					}// end for j	
				} // end if temp
			}// end for i	
			address = PML4_PLUS_ONE(address);
		}// end lopp pn PML4	
		break;

	default:
		ret = -EINVAL;
	}

	return ret;
}


void foo(struct task_struct *tsk) {
	int i;

	if(current->mm != NULL){
		for(i=0;i<SIBLING_PGD;i++){	
			if ((root_sim_processes[i])==(current->pid)){	
				rootsim_load_cr3(pgd_addr[i]);
			}
		}
	}
}


static int rs_ktblmgr_init(void) {

	int ret;
	int i;
	struct kprobe kp;
	void * accesses_row_address;
	
	rootsim_pager = foo;

	mutex_init(&pgd_get_mutex);
	
	#ifdef ACCESSES_HASHBUCKET
		//mutex_init(&hash_mutex);
		printk("MAX_SIZE_BODY_ENTRY_REAL=%d\n",MAX_SIZE_BODY_ENTRY_REAL);
		//printk("N_NODES_PER_BUCKET=%d\n",N_NODES_PER_BUCKET);
		//printk("sizeof(struct mutex)=%u\n",sizeof(struct mutex));
		//printk("sizeof(struct semaphore)=%u\n",sizeof(struct semaphore));
		//printk("sizeof(spinlock_t)=%u\n",sizeof(spinlock_t));
		//printk("sizeof(rwlock_t)=%u\n",sizeof(rwlock_t));
	#endif
	
	// Dynamically allocate a major for the device
	major = register_chrdev(0, "rs_ktblmgr", &fops);
	if (major < 0) {
		ret = major;
		goto failed_chrdevreg;
	}
	printk("major for ktblmgr is %d\n",major);
	goto allocate; /*registrazione device OLD STYLE*/        

	allocate:

	// Preallocate pgd
	for (i = 0; i < SIBLING_PGD; i++) {
        
		original_view[i] = NULL;

		if ( ! (mm_struct_addr[i] = kmalloc(sizeof(struct mm_struct), GFP_KERNEL)))
			goto bad_alloc;

		if (!(pgd_addr[i] = (void *)get_zeroed_page(GFP_KERNEL))) {
			kfree(mm_struct_addr[i]);
			goto bad_alloc;
		}
		mm_struct_addr[i]->pgd = pgd_addr[i];
		if ((void *)pgd_addr[i] != (void *)((struct mm_struct *)mm_struct_addr[i])->pgd) {
			printk("bad referencing between mm_struct and pgd\n");
			goto bad_alloc;
		}
		managed_pgds++;
	}

	printk(KERN_INFO "Correctly allocated %d sibling pgds\n", managed_pgds);     
    //debug code
    	//original_view[0]=current->mm;
    	/*for(i=0;i<SIBLING_PGD;i++){
			if(original_view[i]!=NULL)
				printk("original_view[%d]=%p\n",i,original_view[i]);
		}*/
    //end debug code
    
	// Get a kernel probe to access flush_tlb_all
	memset(&kp, 0, sizeof(kp));
	kp.symbol_name = "flush_tlb_all";
	if (!register_kprobe(&kp)) {
		flush_tlb_all_lookup = (void *) kp.addr;
		unregister_kprobe(&kp);
	} 

	return 0;

    failed_chrdevreg:
	return ret;
 
    bad_alloc:
	printk(KERN_ERR "rs_ktblmgr: something wrong while preallocatin pgds\n");
	return -1;
}


static void rs_ktblmgr_cleanup(void) {

	int i;
	rootsim_pager = NULL;
	unregister_chrdev(major, "rs_ktblmgr");

	for (; managed_pgds > 0; managed_pgds--) {
		__free_pages((void*)mm_struct_addr[managed_pgds-1]->pgd,0); /*free di mm_struct_addr[managed_pgds -1]->pgd,0) perchè era un BUG*/
		kfree(mm_struct_addr[managed_pgds-1]);

	}
}

#endif	/* HAVE_LINUX_KERNEL_MAP_MODULE */
