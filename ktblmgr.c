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

//#define ACCESSES_ABR

#ifdef ACCESSES_ABR
	#define OFFSET_ZONE_BIT 21
	#define ZONE2M_NUMBER(address) (unsigned int)(((unsigned long)address >> OFFSET_ZONE_BIT)&0x7ffffff)
	#define NUMBER_BYTES 64
	
	typedef struct{
		void * node_dx;
		void * node_sx;
		unsigned int key;
		unsigned char pages[NUMBER_BYTES];
	}node;
	
	//gestione pila ausiliaria per visita in-ordine iterativa
	typedef struct {
		void * this;
		void * next;
		unsigned char flag;
	}stack_frame_aux;
	
	#define SIZE_STACK_FRAME sizeof(stack_frame_aux)
	
	stack_frame_aux * stack;
	
	void * stack_push(void * this_node, unsigned char this_flag){
		stack_frame_aux * new_stack_frame = kzalloc(SIZE_STACK_FRAME,GFP_KERNEL);
		new_stack_frame->this=this_node;
		new_stack_frame->next=stack;
		new_stack_frame->flag=this_flag;
		stack = new_stack_frame;
		return;
	}
	
	stack_frame_aux * stack_pop(){
		stack_frame_aux * pop = stack;
		stack = stack->next;
		return pop;
	}
	//
	
	#define SIZE_NODE sizeof(node)
	
	node * abr;
	
	struct mutex mutex_node;
	
	void add_node(unsigned int);
	//node * add_node_aux(node *,unsigned int);
	
	void add_node(unsigned int pde){
		mutex_lock(&mutex_node);
		//abr = add_node_aux(abr,pde);
		if(abr==NULL) {
			abr = kzalloc(SIZE_NODE,GFP_KERNEL);
			abr->key = pde;
			goto end_add;
		}
		if(abr->key==pde) {
			goto end_add;	
		}
		node * walker = abr;
		node * walker1;
		while(walker!=NULL){
			if(pde == walker->key)
				goto end_add;
			if(pde > walker->key) {
				walker1=walker;
				walker=walker->node_dx;
			}
			else {
				walker1=walker;
				walker=walker->node_sx;
			}
		}
		node * last_add = kzalloc(SIZE_NODE,GFP_KERNEL);
		last_add->key=pde;
		if(pde > walker1->key)
			walker1->node_dx=last_add;
		else
			walker1->node_sx=last_add;
		end_add: mutex_unlock(&mutex_node);
		return;
	}
	/*node * add_node_aux(node * walker, unsigned int pde) {
		//printk("pde=%d\n",pde);
			if(walker==NULL) {
				walker = kzalloc(SIZE_NODE,GFP_KERNEL);
				walker->key = pde;
	        	return walker;
			}
			if(walker->key==pde) {
				return walker;	
			}
			if(pde > walker->key) {
				walker->node_dx = add_node_aux(walker->node_dx,pde);
				return walker;
			}
			else {
				walker->node_sx=add_node_aux(walker->node_sx,pde);
				return walker;
			}
	}*/
	
	unsigned char search_node(unsigned int pde) {
		mutex_lock(&mutex_node);
		node * walker = abr;
		unsigned char ret = 0;
		while(walker!=NULL) {
			if(walker->key == pde) {
				ret=1;
				goto end_search;
			}
			if(pde > walker->key)
				walker = walker->node_dx;
			else
				walker=walker->node_sx;
		}
		end_search: mutex_unlock(&mutex_node);
		return ret;
	}
	
	/*void in_order(node * walker){
		if(walker==NULL)
			return;
		else {
			in_order(walker->node_sx);
			printk("%d\n",walker->key);
			in_order(walker->node_dx);
		}
	}*/
	
	void in_order_iterative(){
		mutex_lock(&mutex_node);
		node * aux;
		if(abr==NULL) {
			printk("empty bst\n");
			return;
		}
		stack_push(abr,0);
		while(stack!=NULL){
			stack_frame_aux * stack_walker = stack_pop();
			aux = stack_walker->this;
			if(stack_walker->flag==1){
				//do something on the node
				printk("pde_number=%d\n",aux->key);
				kfree(stack_walker);
			}
			else {
				
				if(aux->node_dx!=NULL)
					stack_push(aux->node_dx,0);
				stack_push(aux,1);
				if(aux->node_sx!=NULL)
					stack_push(aux->node_sx,0);
			}
		}
		mutex_unlock(&mutex_node);
		
	}
	
#endif

#define ACCESSES_LIST

#ifdef ACCESSES_LIST
	#define N2MZONE 71303168
	#define BODY_SIZE_ELEMENTS 64
	#define BODY_SIZE_BYTE 1
	#define OFFSET_ZONE_BIT 21
	#define ZONE2M_NUMBER(address) (unsigned int)(((unsigned long)address >> OFFSET_ZONE_BIT)&0x7ffffff)
	void * accesses[N2MZONE];
	struct mutex mutex_node;
	void add_node(unsigned int pd_entry) {
		mutex_lock(&mutex_node);
		if(accesses[pd_entry]==NULL) {
			accesses[pd_entry] = kcalloc(BODY_SIZE_ELEMENTS,BODY_SIZE_BYTE,GFP_KERNEL);
			mutex_unlock(&mutex_node);
			return;
		}
		else {
			mutex_unlock(&mutex_node);
			return;
		}
	}
	unsigned char search_node(unsigned int pd_entry) {
		mutex_lock(&mutex_node);
		void * ret = accesses[pd_entry];
		mutex_unlock(&mutex_node);
		if(ret!=NULL)
			return 1;
		else
			return 0;
	}
	void iterate(){
		mutex_lock(&mutex_node);
		int i;
		for(i=0; i<N2MZONE; i++){
			if(accesses[i]!=NULL)
				printk("pde %d is busy\n",i);
		}
		mutex_unlock(&mutex_node);
		return;
	}
	
#endif

//#define ACCESSES_MATRIX

#ifdef ACCESSES_MATRIX 
 #define GROUP_SIZE_BIT 8
 #define GROUP_SIZE_BYTE 1
 #define GROUP_SIZE_BIT_LOG 3
 #define N2MZONE 71303168
 #define NGROUPS SIBLING_PGD / GROUP_SIZE_BIT
 //#define THREAD_GROUP_INDEX(pgd_index) (unsigned char)(pgd_index/GROUP_SIZE_BIT)
 #define THREAD_GROUP_INDEX(pgd_index) (unsigned char) (pgd_index >> GROUP_SIZE_BIT_LOG)
 //#define BIT_NUMBER (pgd_index) (unsigned char)((pgd_index)-((pgd_index)*(THREAD_GROUP_INDEX(pgd_index))))
 #define offset_zone 21
 #define ZONE2M_NUMBER(address) (unsigned int)(((unsigned long)address >> offset_zone)&0x7ffffff)
 #define BIT_PLACE(pgd_index) (pgd_index -(GROUP_SIZE_BIT * (THREAD_GROUP_INDEX(pgd_index))))
 void * accesses [NGROUPS];
 char * accesses_row;
 char bit_set[GROUP_SIZE_BIT]={1,2,4,8,16,32,64,128};
 char bit_reset[GROUP_SIZE_BIT]={254,253,251,247,239,223,191,127};
 unsigned char active_groups;
 
 #define ACCESSES_ROW(pgd_index) (accesses[THREAD_GROUP_INDEX(pgd_index)])
 #define SET_ACCESSES(pgd_index,fault_address) (((char *)ACCESSES_ROW(pgd_index))[ZONE2M_NUMBER(fault_address)] |= bit_set[BIT_PLACE(pgd_index)])
 #define RESET_ACCESSES(pgd_index,entry) (((char *)ACCESSES_ROW(pgd_index))[entry] &= bit_reset[BIT_PLACE(pgd_index)])
 /*void set_accesses(unsigned char pgd_index,void * fault_address){
 	unsigned int page_entry = ZONE2M_NUMBER(fault_address);
 	unsigned char thread_index = THREAD_GROUP_INDEX(pgd_index);
 	//unsigned char bit_place = pgd_index - (GROUP_SIZE_BIT * thread_index);
 	unsigned char bit_place = BIT_PLACE(pgd_index);
 	//char * accesses_row = accesses[thread_index];
 	char * accesses_row = ACCESSES_ROW(pgd_index);
	accesses_row[page_entry] |= bit_set[bit_place];
	return;
 }*/
 
 /*void reset_accesses(unsigned char pgd_index){
 	unsigned char thread_index = THREAD_GROUP_INDEX(pgd_index);
 	unsigned char bit_place = pgd_index - (GROUP_SIZE_BIT * thread_index);
 	char * accesses_row = accesses[thread_index];
 	int i;
 	for(i=0;i<N2MZONE;i++) {
 		accesses_row[i] = accesses_row[i] & bit_reset[bit_place];
	}
 	return;
 }*/
 

 /*void reset_accesses_2(unsigned char pgd_index,unsigned int entry){
  	unsigned char thread_index = THREAD_GROUP_INDEX(pgd_index);
 	unsigned char bit_place = pgd_index - (GROUP_SIZE_BIT * thread_index);
 	//unsigned int entry = ZONE2M_NUMBER(my_pd_entry);
 	char * accesses_row = accesses[thread_index];
 	//accesses_row[entry] = accesses_row[entry] & bit_reset[bit_place];
 	accesses_row[entry] &= bit_reset[bit_place];
 	return;
 }*/	
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
			 					//#ifdef ACCESSES_ABR
			 					//#ifdef ACCESSES_LIST
			 						if(search_node(ZONE2M_NUMBER(target_address))==1)
			 							printk("node %d present\n",ZONE2M_NUMBER(target_address));
			 						else
			 							printk("error: node %d not present\n",ZONE2M_NUMBER(target_address));
			 					//#endif
			 					//printk("zone number=%u\n",ZONE2M_NUMBER(target_address));
			 					my_pd = (void **)__va((ulong) my_pdp[PDP(target_address)] & 0xfffffffffffff000);
			 					if(my_pd[PDE(target_address)]!=NULL){
			 						printk("my_pd[%d]!=NULL\n",PDE(target_address));
			 						return 0;
								}
			 					else {
			 						printk("my_pd[%d]=NULL\n",PDE(target_address));
			 						my_pd[PDE(target_address)]=(ulong)ancestor_pd[PDE(target_address)];
			 						#ifdef ACCESSES_MATRIX
			 							//set_accesses(i,target_address);
			 							SET_ACCESSES(i,target_address);
			 						#endif
			 						
			 						
			 						//accesses[accesses_table_entry(target_address)]=1;
			 						//printk("accesses[%d]=%d\n",accesses_table_entry(target_address),accesses[accesses_table_entry(target_address)]);
			 						
			 						return 1;
			 					}
			 				}
			 				else {
			 					printk("ancestor_pd[%d]=NULL\n",PDE(target_address));
			 					#ifdef ACCESSES_LIST
			 						add_node(ZONE2M_NUMBER(target_address));
			 					#endif
			 					
			 					#ifdef ACCESSES_ABR
			 						add_node(ZONE2M_NUMBER(target_address));
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
				#ifdef ACCESSES_MATRIX
					if(accesses[THREAD_GROUP_INDEX(i)]==NULL){
						accesses[THREAD_GROUP_INDEX(i)]=vmalloc(N2MZONE*GROUP_SIZE_BYTE);
						if(accesses[THREAD_GROUP_INDEX(i)]==NULL) {
							ret = -1;
							goto pgd_get_done;
						}
						memset(accesses[THREAD_GROUP_INDEX(i)],0,N2MZONE*GROUP_SIZE_BYTE);
						active_groups++;
					}
				#endif
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
                        				
                        				//#ifdef ACCESSES_ABR
                        				//#ifdef ACCESSES_LIST
                        					//if(arg == 0) {
                        						ancestor_pd = (void **) __va((ulong) ancestor_pdp[j] & 0xfffffffffffff000);
                        						for(k=0; k<512; k++){
													if(ancestor_pd[k]!=NULL){
														pd_entry = k;
														zone_num_calc = j << 9;
														pd_entry |= zone_num_calc;
														zone_num_calc = i << 18;
														pd_entry |= zone_num_calc;
														add_node(pd_entry);
													}
					    						}
											//}
										//#endif
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
                       			#ifdef ACCESSES_MATRIX
                       				for(k=0; k<512; k++) {
                       					if(my_pd[k]!=NULL){
                       						pd_entry = k;
                       						zone_num_calc = j << 9;
                       						pd_entry |= zone_num_calc;
                       						zone_num_calc = i << 18;
                       						pd_entry |= zone_num_calc;
                       						RESET_ACCESSES(arg,pd_entry);
										}	
									}
                       			#endif
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
			
			/*#ifdef ACCESSES_MATRIX
					reset_accesses(arg);
			#endif*/
			
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
		
		#ifdef ACCESSES_MATRIX
			
			/*printk("Printing working set of thread n°%d.\n",arg);
			if(pgd_addr[arg]==NULL){
				printk("Can't show information about working set\n");
				goto exit_from_info;
			}
			unsigned char thread_index = THREAD_GROUP_INDEX(arg);
			unsigned char bit_place = arg - (GROUP_SIZE_BIT * thread_index);
			accesses_row = accesses[thread_index];
			for(i=0;i<N2MZONE;i++){
				if((accesses_row[i] &  bit_set[bit_place]) ==  bit_set[bit_place])
					printk("WORKING SET: zone number=%d\n",i);
			}*/
			
			printk("active_groups=%d\n",active_groups);
			printk("Pages accesses\n");
			for(i=0; i<N2MZONE; i++) {
				for(j=0; j<active_groups;j++) {
					cell = ((unsigned char)((char *)(accesses[j]))[i]);
					if(cell > 0){
						printk("page %d is busy(group %d)\n",i,j);
					}
				}
			}
			
        #endif
        /*exit_from_info:*/
        
        #ifdef ACCESSES_LIST
        	iterate();
        #endif
        
        #ifdef ACCESSES_ABR
        	//in_order(abr);
        	in_order_iterative();
        #endif
        
        for(i=0;i<SIBLING_PGD;i++) {
        	if(original_view[i]!=NULL) 
        		printk("original_view[%d]=%p\n",i,original_view[i]);
        	printk("root_sim_processes[%d]=%d\n",i,root_sim_processes[i]);
        	
        		
        }
        
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
	
	#ifdef ACCESSES_ABR
		mutex_init(&mutex_node);
	#endif
    #ifdef ACCESSES_LIST
    	mutex_init(&mutex_node);
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
    #ifdef ACCESSES_MATRIX
     accesses[0]=vmalloc(N2MZONE*GROUP_SIZE_BYTE);
     memset(accesses[0],0,N2MZONE*GROUP_SIZE_BYTE);
     if(accesses[0]==NULL) {
     	printk("Error: there isn't structure to track memory accesses\n");
     	return -1;
     }
     else {
     	printk("accesses[0]=%p\n",accesses[0]);
     	active_groups++;
	 }
	 
	
	 
	 /*for(i=0;i<NGROUPS; i++) {
	 	accesses[i]=vmalloc(N2MZONE*GROUP_SIZE_BYTE);
	 	memset(accesses[i],0,N2MZONE*GROUP_SIZE_BYTE);
	 	active_groups++;	
	 }*/
	 
	 /*for(i=0;i<NGROUPS;i++) {
	 	accesses[i]=vmalloc(N2MZONE*GROUP_SIZE_BYTE);	
	 }*/
     
    #endif
     
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
	#ifdef ACCESSES_MATRIX
		for(i=0; i < active_groups; i++) {
			vfree(accesses[i]);
		}
	#endif

}

#endif	/* HAVE_LINUX_KERNEL_MAP_MODULE */
