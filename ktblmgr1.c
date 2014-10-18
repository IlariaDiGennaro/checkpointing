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


/// Device class being created
static struct class *dev_cl = NULL;

/// Device being created
static struct device *device = NULL;

/// Only one process can access this device (before spawning threads!)
static DEFINE_MUTEX(rs_ktblmgr_mutex);

struct mutex pgd_get_mutex;
struct mm_struct *mm_struct_addr[SIBLING_PGD];
void *pgd_addr[SIBLING_PGD];
unsigned int managed_pgds = 0;
struct mm_struct *original_view[SIBLING_PGD];

/* stack of auxiliary frames - used for chnage view */
int stack_index = AUXILIARY_FRAMES - 1;
void * auxiliary_frames[AUXILIARY_FRAMES];

int root_sim_processes[SIBLING_PGD]={[0 ... (SIBLING_PGD-1)] = -1};

//#define MAX_CROSS_STATE_DEPENDENCIES 1024
int currently_open[SIBLING_PGD][MAX_CROSS_STATE_DEPENDENCIES]; 
int open_index[SIBLING_PGD]={[0 ... (SIBLING_PGD-1)] = -1};

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
	release:rs_ktblmgr_release
};


/// This is to access the actual flush_tlb_all using a kernel proble
void (*flush_tlb_all_lookup)(void) = NULL;


int root_sim_page_fault(struct pt_regs* regs, long error_code){
 	void* target_address;
	void ** my_pgd;
	void ** my_pdp;
	void** target_pdp_entry;
	void** ancestor_pdp;
	ulong i;
	void* cr3;
	ulong* auxiliary_stack_pointer;
	ulong hitted_object;

	if(current->mm == NULL) return 0;  /* this is a kernel thread - not a rootsim thread */
                                           /* i kernel thread hanno current->mm=NULL di regola */

	target_address = (void*)read_cr2(); 

	/* discriminate whether this is a classical fault or a root-sim proper fault */

	for(i=0;i<SIBLING_PGD;i++){	
		if ((root_sim_processes[i])==(current->pid)){	


			if((PML4(target_address)<restore_pml4) || (PML4(target_address))>=(restore_pml4+restore_pml4_entries)) return 0; /* a fault outside the root-sim object zone - it needs to be handeld by the traditional fault manager */
			
			my_pgd =(void**) pgd_addr[i];
			my_pdp =(void*) my_pgd[PML4(target_address)];
			my_pdp = __va((ulong)my_pdp & 0xfffffffffffff000); /*52 "uno" e 12 "zero" -> scarto i bit di controllo*/ 
			if((void*)my_pdp[PDP(target_address)] != NULL) return 0; /* faults at lower levels than PDP - need to be handled by traditional fault manager */


#ifdef ON_FAULT_OPEN /*ON_FAULT_OPEN -> macro di debug*/
			ancestor_pdp =(void*) ancestor_pml4[PML4(target_address)];
			ancestor_pdp = __va((ulong)ancestor_pdp & 0xfffffffffffff000);
			my_pdp[PDP(target_address)] = ancestor_pdp[PDP(target_address)];

			rootsim_load_cr3(pgd_addr[i]);
		
/* to be improved with selective tlb invalidation */

			return 1;

#else
			rs_ktblmgr_ioctl(NULL,IOCTL_UNSCHEDULE_ON_PGD,(int)i); 

#endif
			hitted_object = (PML4(target_address) - restore_pml4)*512 + PDP(target_address) ;
			

			auxiliary_stack_pointer = regs->sp;
			auxiliary_stack_pointer--;
			
		        copy_to_user((void*)auxiliary_stack_pointer,(void*)&regs->ip,8);	
			auxiliary_stack_pointer--;
		        copy_to_user((void*)auxiliary_stack_pointer,(void*)&hitted_object,8);	
			auxiliary_stack_pointer--;
		        copy_to_user((void*)auxiliary_stack_pointer,(void*)&i,8);	

			regs->sp = auxiliary_stack_pointer;
			regs->ip = callback;

			return 1;
		}/*end if*/ 
	}/*end for*/
	return 0;
        
       /* NON ESEGUITO

	if (!target_pdp_entry){ /* root-sim fault - open access and notify */
		
	//	ancestor_pdp =(void*) ancestor_pml4[PML4(target_address)];
	//	my_pdp[PDP(target_address)] = ancestor_pdp[PDP(target_address)]; /* access opened */
	//        return 1;	
	//}
	//else{ /* classical fault - just push the fault to the original handler */
	//	return 0;
        //
	//}
        
       
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
      	int i,j;
	int pml4, pdp;
	int involved_pml4;
	void** pgd_entry;
	void** temp;
	void* address;

	/* already logged by ancestor set */
	pml4 = restore_pml4; 
	involved_pml4 = restore_pml4_entries;

	for (j=0;j<SIBLING_PGD;j++){
		if(original_view[j]!=NULL){ /* need to recover memory used for PDPs that have not been deallocated */                        

			pgd_entry = (void**)pgd_addr[j];/*ho messo j al posto di i, era un BUG*/

			for (i=0; i<involved_pml4; i++){
			
				temp = pgd_entry[pml4];
				
				temp = (void*)((ulong) temp & 0xfffffffffffff000);	
				address = (void*)__va(temp);
				if(address!=NULL){
					__free_pages(address, 0);
				}
				pgd_entry[pml4] = ancestor_pml4[pml4];
                                pml4++; /*BUG pml4 non era mai incrementato*/

			}// end for i
			original_view[j]=NULL;
                        pml4=restore_pml4;/*BUG -> reset di pml4 per ciclo successivo */
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
	int i,j,z;
	void ** my_pgd;
	void ** my_pdp;
	void** ancestor_pdp;
	void* cr3;
	void** pgd_entry;
	void** source_pgd_entry;
	void* pdp_entry;
	void* pde_entry;
	void* pte_entry;
	void** temp;
	void** temp1;
	void** temp2;
	int descriptor;
	struct vm_area_struct *mmap;
	void* address;
	int pml4, pdp;
	int involved_pml4;
	void* source_pdp;
	int scheduled_object;
	int* scheduled_objects;
	int scheduled_objects_count;
	int object_to_close;

	char* aux;
	char* aux1;

	switch (cmd) {

	case IOCTL_INIT_PGD:
		break;

	case IOCTL_REGISTER_THREAD:
	
		root_sim_processes[arg] = current->pid;
		break;

	case IOCTL_DEREGISTER_THREAD:

		root_sim_processes[arg] = -1;
		break;

	case IOCTL_SET_ANCESTOR_PGD:

		ancestor_pml4 = (void**)current->mm->pgd;
		break;

	case IOCTL_GET_PGD:/*thread piattaforma*/
		
		mutex_lock(&pgd_get_mutex);
		for (i = 0; i < SIBLING_PGD; i++) {
			if (original_view[i] == NULL) {
				memcpy((void *)pgd_addr[i], (void *)(current->mm->pgd), 4096);
/* copia della pgd originale per non avere subito dei page fault */
				original_view[i] = current->mm;
				descriptor = i;
				ret = descriptor;
				goto pgd_get_done;
			}/*end if*/
		}/*end for*/
		ret = -1;
		pgd_get_done:
		mutex_unlock(&pgd_get_mutex);
goto bridging_from_get_pgd;
		break;

	case IOCTL_RELEASE_PGD:
		
goto bridging_from_pgd_release; 
back_to_pgd_release:
		rootsim_load_cr3(current->mm->pgd);
		if (original_view[arg] != NULL) {
			original_view[arg] = NULL;
			ret = 0;
			break;
		}
		else{

		}

		break;

	case IOCTL_SCHEDULE_ON_PGD:	
		
		descriptor = ((ioctl_info*)arg)->ds;
		scheduled_objects_count = ((ioctl_info*)arg)->count;
		scheduled_objects = ((ioctl_info*)arg)->objects;

		
		if (original_view[descriptor] != NULL) { //sanity check

			for(i=0;i<scheduled_objects_count;i++){

			//scheduled_object = TODO COPY FROM USER;
		        copy_from_user((void*)&scheduled_object,(void*)&scheduled_objects[i],sizeof(int));	
			open_index[descriptor]++;
			currently_open[descriptor][open_index[descriptor]]=scheduled_object;
			
			pml4 = restore_pml4 + OBJECT_TO_PML4(scheduled_object);
			my_pgd =(void**) pgd_addr[descriptor];
			my_pdp =(void*) my_pgd[pml4];
			my_pdp = __va((ulong)my_pdp & 0xfffffffffffff000);

			ancestor_pdp =(void*) ancestor_pml4[pml4];
			ancestor_pdp = __va((ulong)ancestor_pdp & 0xfffffffffffff000);

			/* actual opening of the PDP entry */
			my_pdp[OBJECT_TO_PDP(scheduled_object)] = ancestor_pdp[OBJECT_TO_PDP(scheduled_object)];
			}// end for 

			/* actual change of the view on memory */
			root_sim_processes[descriptor] = current->pid;
			rootsim_load_cr3(pgd_addr[descriptor]);
			ret = 0;
		}else{
			 ret = -1;
		}
		break;


	case IOCTL_UNSCHEDULE_ON_PGD:	

		descriptor = arg;

		if ((original_view[descriptor] != NULL) && (current->mm->pgd != NULL)) { //sanity check

			root_sim_processes[descriptor] = -1;
			rootsim_load_cr3(current->mm->pgd);

			for(i=open_index[descriptor];i>=0;i--){

				object_to_close = currently_open[descriptor][i];
	
			
				pml4 = restore_pml4 + OBJECT_TO_PML4(object_to_close);

				my_pgd =(void**) pgd_addr[descriptor];
				my_pdp =(void*) my_pgd[pml4];
				my_pdp = __va((ulong)my_pdp & 0xfffffffffffff000);


				/* actual closure of the PDP entry */
	
				my_pdp[OBJECT_TO_PDP(object_to_close)] = NULL;
			}
			open_index[descriptor] = -1;
			ret = 0;
		}else{
			ret = -1;
		}

		break;

	case IOCTL_INSTALL_PGD:	//
		if (original_view[arg] != NULL) {

			
			root_sim_processes[arg] = current->pid;
			rootsim_load_cr3(pgd_addr[arg]);
			ret = 0;
			break;
                        //


			current->mm = mm_struct_addr[arg];
			current->active_mm = original_view[arg];/* 30-1-2014 */
			atomic_inc(&original_view[arg]->mm_count); /* 30-1-2014 */
			current->mm->pgd = (void*)(pgd_addr[arg]);


			flush_cache_all();
			cr3 = (void*)__pa(current->mm->pgd);
			asm volatile("movq %%CR3, %%rax; andq $0x0fff,%%rax; movq %0, %%rbx; orq %%rbx,%%rax; movq %%rax,%%CR3"::"m" (cr3));
			
			ret = 0;
			break;
		}
		else{
		 	printk("bad pgd install\n");
		}

		break;

	case IOCTL_GET_INFO_PGD:
	
		pgd_entry = (void**)current->mm->pgd;
		for(i=0;i<512;i++){
			if (*(pgd_entry + i) != NULL){
	
			}
		}	

		break;

	case IOCTL_GET_INFO_VMAREA:
		mmap = current->mm->mmap;

		for(i=0;mmap;i++){
			mmap = mmap->vm_next;
		}	

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
                //
		if(current->mm != NULL){
			root_sim_processes[arg] = -1;
			rootsim_load_cr3(current->mm->pgd);
		}

			ret = 0;
			break;
                //
		if (original_view[arg] != NULL) {

			aux = (char*)current->mm;
			aux1 = (char*)original_view[arg];

			printk("\n");
			current->mm = original_view[arg];
			atomic_dec(&original_view[arg]->mm_count); /* 30-1-2014 */

			cr3 = (void*)__pa(current->mm->pgd);
			asm volatile("movq %%CR3, %%rax; andq $0x0fff,%%rax; movq %0, %%rbx; orq %%rbx,%%rax; movq %%rax,%%CR3"::"m" (cr3));


			ret = 0;
			break;
		}

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

	case IOCTL_CHANGE_MODE_VMAREA:
			
		mmap = current->mm->mmap;

		for(i=0;mmap;i++){
			
			if (((void*)arg >= (void*)mmap->vm_start) && ((void*)(arg)<=(void*)mmap->vm_end)){
	
				goto redirect;

			}
	
			mmap = mmap->vm_next;

		}	
redirect:

		/* logging current snapshot and redirecting the vmarea to auxiliary vmarea ops table */
		changed_mode_mmap = mmap;
	
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

;	
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


bridging_from_get_pgd:
		arg = ret; /*da qui in poi esegue tutto finchè non trova un break ignorando il "case"*/
	case IOCTL_CHANGE_VIEW:

			flush_cache_all();


			/* already logged by ancestro set */
			pml4 = restore_pml4; 
			involved_pml4 = restore_pml4_entries;

			pgd_entry = (void**)pgd_addr[arg];


			for (i=0; i<involved_pml4; i++){ 


				address = (void *)__get_free_pages(GFP_KERNEL, 0); /* allocate and reset new PDP */
				memset(address,0,4096);
			
				temp = pgd_entry[pml4];

				
				temp = (void*)((ulong) temp & 0x0000000000000fff);	
				address = (void*)__pa(address);
				temp = (void*)((ulong)address | (ulong)temp);

				pgd_entry[pml4] = temp;

				pml4++; 

			}

		break;

bridging_from_pgd_release:/*da qui in poi esegue tutto fino al primo break*/

	case IOCTL_RESTORE_VIEW:


			/* already logged by ancestor set */
			pml4 = restore_pml4; 
			involved_pml4 = restore_pml4_entries;

			
			pgd_entry = (void**)pgd_addr[arg];


			for (i=0; i<involved_pml4; i++){
			

			
				temp = pgd_entry[pml4];

				
// TO PATCH IMMEDIATELY
					
				temp = (void*)((ulong) temp & 0xfffffffffffff000);	
				address = (void*)__va(temp);
				if(address!=NULL){
					__free_pages(address, 0);
				}
				
				pgd_entry[pml4] = ancestor_pml4[pml4];

				pml4++;

			}



goto back_to_pgd_release;

		break;

	case IOCTL_SYNC_SLAVES:

		break;

	case IOCTL_SCHEDULE_ID:
		
		break;

	case IOCTL_UNSCHEDULE_CURRENT:

		break;

	default:
		ret = -EINVAL;
	}

	return ret;

}



void foo(struct task_struct *tsk) {
	int i;
	void* cr3;

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

	rootsim_pager = foo;

	mutex_init(&pgd_get_mutex);

	// Dynamically allocate a major for the device
	major = register_chrdev(0, "rs_ktblmgr", &fops);
	if (major < 0) {
		ret = major;
		goto failed_chrdevreg;
	}
	printk("major for ktblmgr is %d\n",major);
	goto allocate; /*registrazione device OLD STYLE*/
        /* NON ESEGUITO
	// Create a class for the device
	dev_cl = class_create(THIS_MODULE, "rootsim");
	if (IS_ERR(dev_cl)) {
		ret = PTR_ERR(dev_cl);
		goto failed_classreg;
	}

	// Create a device in the previously created class
	device = device_create(dev_cl, NULL, MKDEV(major, 0), NULL, "ktblmgr");
	if (IS_ERR(device)) {
		ret = PTR_ERR(device);
		goto failed_devreg;
	}


	// Create sysfs endpoints
	// dev_attr_multimap comes from the DEVICE_ATTR(...) at the top of this module
	// If this call succeds, then there is a new file in:
	// /sys/devices/virtual/rootsim/ktblmgr/multimap
	// Which can be used to dialogate with the driver
	ret = device_create_file(device, &dev_attr_multimap);
	if (ret < 0) {
		printk(KERN_WARNING "rs_ktblmgr: failed to create write /sys endpoint - continuing without\n");
	}

	// Initialize the device mutex
	mutex_init(&rs_ktblmgr_mutex); 
        */        

	allocate:

	// Preallocate pgd
	for (i = 0; i < SIBLING_PGD; i++) {

		original_view[i] = NULL;

		if ( ! (mm_struct_addr[i] = kmalloc(sizeof(struct mm_struct), GFP_KERNEL)))
			goto bad_alloc;

		if (!(pgd_addr[i] = (void *)__get_free_pages(GFP_KERNEL, 0))) {
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

	// Get a kernel probe to access flush_tlb_all
	memset(&kp, 0, sizeof(kp));
	kp.symbol_name = "flush_tlb_all";
	if (!register_kprobe(&kp)) {
		flush_tlb_all_lookup = (void *) kp.addr;
		unregister_kprobe(&kp);
	} 

	return 0;

    /* NON ESEGUITO 
    failed_devreg:
	class_unregister(dev_cl);
	class_destroy(dev_cl);
    failed_classreg:
	unregister_chrdev(major, "rs_ktblmgr");
    */
    failed_chrdevreg:
	return ret;
 

    bad_alloc:
	printk(KERN_ERR "rs_ktblmgr: something wrong while preallocatin pgds\n");
	return -1;
}



static void rs_ktblmgr_cleanup(void) {


	rootsim_pager = NULL;
	unregister_chrdev(major, "rs_ktblmgr");

	for (; managed_pgds > 0; managed_pgds--) {
		__free_pages((void*)mm_struct_addr[managed_pgds-1]->pgd,0); /*free di mm_struct_addr[managed_pgds -1]->pgd,0) perchè era un BUG*/
		kfree(mm_struct_addr[managed_pgds-1]);

	}

}

#endif	/* HAVE_LINUX_KERNEL_MAP_MODULE */
