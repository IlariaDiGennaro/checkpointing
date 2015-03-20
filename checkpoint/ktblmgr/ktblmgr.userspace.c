#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/mman.h>

#include "ktblmgr.h"

	int fd;
	int ret;
	void* addr;
	void* addr1;
	void* start;
	void* end;
	int pgd_ds;
	ioctl_info info;

void ** dummy;
	
#define NUM_THREADS 4

char*buff[4096];

void (*callback_function)(void)  ;

void my_print(void) {

	unsigned long id = -1;
	void *addr  = NULL;

//__attribute__ ((regparm(0))) void my_print(ulong addr) {

	asm volatile("push %rax");
	asm volatile("push %rbx");
	asm volatile("push %rcx");
	asm volatile("push %rdx");
	asm volatile("push %rdi");
	asm volatile("push %rsi");
	asm volatile("push %r8");
	asm volatile("push %r9");
	asm volatile("push %r10");
	asm volatile("push %r11");
	asm volatile("push %r12");
	asm volatile("push %r13");
	asm volatile("push %r14");
	asm volatile("push %r15");
	asm volatile("movq 0x10(%%rbp), %%rax; movq %%rax, %0" : "=m"(addr) : );
	asm volatile("movq 0x8(%%rbp), %%rax; movq %%rax, %0" : "=m"(id) : );
//	asm volatile("movq 0x8(%%rbp), %%rax; movq %%rax, %0" : "=m"(addr) : );
	printf("rootsim callback received by the kernel need to sync, pointer passed is %p - hitted object is %u\n", addr,id);
	asm volatile("pop %r15");
	asm volatile("pop %r14");
	asm volatile("pop %r13");
	asm volatile("pop %r12");
	asm volatile("pop %r11");
	asm volatile("pop %r10");
	asm volatile("pop %r9");
	asm volatile("pop %r8");
	asm volatile("pop %rsi");
	asm volatile("pop %rdi");
	asm volatile("pop %rdx");
	asm volatile("pop %rcx");
	asm volatile("pop %rbx");
	asm volatile("pop %rax");
	asm volatile("addq $0x10 , %rsp ; popq %rbp ;  addq $0x8, %rsp ; retq");
//	asm volatile("popq %rbp ; addq 0x8, %rsp ; retq");
//	asm volatile("leaveq ; addq 0x8, %rsp ; retq");
}

void handler(){

     printf("page fault or INT occurred - restoring original view\n");
     ioctl(fd,IOCTL_UNINSTALL_PGD,pgd_ds);
     ioctl(fd,IOCTL_RELEASE_PGD,pgd_ds);
     exit(0);

}

void cross_checker(){
	printf("started cross checker\n");
	while(1){
		sleep(1);
		printf("cross checker is alive\n");
		printf("char found at addr is %c\n",((char*)addr)[0]);
		fflush(stdout);
	}
}

void root_sim_thread(){
	int pgd_ds, ret;

	printf("started root-sim_thread\n");
	fflush(stdout);


	pgd_ds = ioctl(fd, IOCTL_GET_PGD);  //ioctl call 
	printf("rootsim thread: pgd descriptor is %d\n",pgd_ds);
	fflush(stdout);


     	ioctl(fd,IOCTL_CHANGE_VIEW,pgd_ds);
	printf("root-sim thread changed view\n");
	fflush(stdout);

//	ioctl(fd, IOCTL_REGISTER_THREAD,pgd_ds);  //ioctl call 
//	printf("root-sim thread registered\n");
//	fflush(stdout);


	ret = ioctl(fd,IOCTL_INSTALL_PGD,pgd_ds);
	printf("rootsim thread: pgd installing returned %d\n",ret);
	fflush(stdout);

//goto end;


/* anything here is access protected - please schedule the right object or trap the faults!! */
	int num_mmap = info.mapped_processes * 2;
	int i;
	char * addr;
	char* addr1;
	char c;
	ioctl_info sched_info;

	addr = info.addr;
	addr1 = (char*)addr;
	for(i=0;i<(num_mmap/2);i++){
		sched_info.ds = pgd_ds;
		sched_info.id = i;
		ioctl(fd,IOCTL_SCHEDULE_ON_PGD, &sched_info);
 		int size = 2 * 256 * 512 * 4096;
		c = addr[0];
//		addr[0] = 'x';
//		addr[1] = addr[0];
		addr = addr+size;
		printf("\t I read/wrote address %p (found '%c') - in scheduleobject is %d \n",addr,c,i);
		if(i==((int)num_mmap/2-1)) sleep(1);
	}
//goto finalize;
	ioctl(fd,IOCTL_UNSCHEDULE_ON_PGD, pgd_ds);

//goto finalize;
	sched_info.ds = pgd_ds;
	sched_info.id = 0;
	ioctl(fd,IOCTL_SCHEDULE_ON_PGD, &sched_info);

	addr = info.addr;
	addr1 = (char*)addr;
	for(i=0;i<(num_mmap/2);i++){
		sched_info.ds = pgd_ds;
		sched_info.id = i;
	//	ioctl(fd,IOCTL_SCHEDULE_ON_PGD, &sched_info);
 		int size =2 * 256 * 512 * 4096;
		c = addr[0];
//		addr[0] = 'x';
//		addr[1] = addr[0];
		addr = addr+size;
		printf("\t I read/wrote address %p (found '%c') \n",addr,c);
		if(i==((int)num_mmap/2-1)) sleep(1);
	}

finalize:

    	ret = ioctl(fd,IOCTL_UNINSTALL_PGD,pgd_ds);
	printf("pgd uninstalling returned %d\n",ret);
	fflush(stdout);

    	ioctl(fd,IOCTL_RESTORE_VIEW,pgd_ds);


//end:
//	ioctl(fd, IOCTL_DEREGISTER_THREAD,pgd_ds);  //ioctl call 


//	ioctl(fd, IOCTL_DEREGISTER_THREAD,pgd_ds);  //ioctl call 

    	ret = ioctl(fd,IOCTL_RELEASE_PGD,pgd_ds);
	printf("pgd release returned %d\n",ret);


//	pause();
}


int main(int argc, char**argv) {
	
	int i;
	pthread_t tid;
	pthread_t tid_id[NUM_THREADS];
	
	printf("I'm process %d\n",getpid());

        if (argc < 2 ) {printf("too few arguments\n"); exit(-1);}

	fd = open("/dev/ktblmgr", O_RDONLY);

	if (fd == -1) {
		perror("Error in opening file.");
		exit(-1);
	}


	ioctl(fd, IOCTL_INIT_PGD);


	ioctl(fd, IOCTL_GET_CR_REGISTERS);


       
	if (argc == 2 && strcmp(argv[1],"pgdget") == 0){
	//pgd_ds = ioctl(fd, IOCTL_INIT_PGD);  //ioctl call 
			pgd_ds = ioctl(fd, IOCTL_GET_PGD);  //ioctl call 
			printf("pgd descriptor is %d\n",pgd_ds);
	}
	if (argc == 2 && strcmp(argv[1],"pgdrelease") == 0){
		scanf("%d",&pgd_ds);
		pgd_ds = ioctl(fd, IOCTL_RELEASE_PGD, pgd_ds);  //ioctl call 
	}
	
	if (argc == 2 && strcmp(argv[1],"doalljob") == 0){


			signal(SIGSEGV,handler);
//goto skip;
			pgd_ds = ioctl(fd, IOCTL_GET_PGD);  //ioctl call 
			printf("pgd descriptor is %d\n",pgd_ds);


			ret = ioctl(fd,IOCTL_INSTALL_PGD,pgd_ds);
			printf("pgd installing returned %d\n",ret);

//skip:
     			ret = ioctl(fd,IOCTL_GET_INFO_PGD);
			printf("pgd getinfo %d\n",ret);

     			ret = ioctl(fd,IOCTL_GET_INFO_VMAREA);
			printf("vmarea getinfo %d\n",ret);

		for (i=0;i<4096;i++) buff[i]='\0';

	//		addr =  mmap(0x0000000f00000000,4096,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,0,0);
	//		perror("");
	//		printf("mmapping returned addr %p\n",addr);


		//	ret = munmap(addr,4096);
		//	printf("unmapping returned %d\n",ret);

//return;

     			ret = ioctl(fd,IOCTL_UNINSTALL_PGD,pgd_ds);
			printf("pgd uninstalling returned %d\n",ret);

    			ret = ioctl(fd,IOCTL_RELEASE_PGD,pgd_ds);
			printf("pgd release returned %d\n",ret);

// now things are restored 
     			ret = ioctl(fd,IOCTL_GET_INFO_PGD);
			printf("pgd getinfo %d\n",ret);

     			ret = ioctl(fd,IOCTL_GET_INFO_VMAREA);
			printf("vmarea getinfo %d\n",ret);

	}


	if (argc == 2 && strcmp(argv[1],"dommap") == 0){


			signal(SIGSEGV,handler);
			signal(SIGINT,handler);
//goto skip;

//skip:
     			ret = ioctl(fd,IOCTL_GET_INFO_PGD);
			printf("pgd getinfo %d\n",ret);

     			ret = ioctl(fd,IOCTL_GET_INFO_VMAREA);
			printf("vmarea getinfo %d\n",ret);

//		for (i=0;i<4096;i++) buff[i]='\0';

 			int size = (0x1<<12) * 4096;
			addr =  mmap((void*)0x00000106fffff000,size,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED,0,0);
			printf("mmapping returned addr %p\n",addr);

			char *ptr = (char *)addr;
			ptr[0]='a';
			ptr[1] = ptr[0];
			//ptr[size-1] = ptr[0];

//     			ret = ioctl(fd,IOCTL_TRACE_VMAREA,(void*)ptr);
//			printf("vmarea trace %d\n",ret);
//			for (i=0;i<4096;i++) ptr[i]='a'; 
			//addr =  mmap((void*)0x00ff000000000000,4096,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,0,0);
	//		perror("");
	//		printf("mmapping returned addr %p\n",addr);


		//	ret = munmap(addr,4096);
		//	printf("unmapping returned %d\n",ret);

//return;

     			ret = ioctl(fd,IOCTL_GET_INFO_PGD);
			printf("pgd getinfo %d\n",ret);

     			ret = ioctl(fd,IOCTL_GET_INFO_VMAREA);
			printf("vmarea getinfo %d\n",ret);

     			ret = ioctl(fd,IOCTL_TRACE_VMAREA,(void*)ptr);
			printf("vmarea trace %d\n",ret);

	}

	if (argc == 2 && strcmp(argv[1],"dommapandpages") == 0){


			signal(SIGSEGV,handler);
			signal(SIGINT,handler);
//goto skip;

//skip:
     			ret = ioctl(fd,IOCTL_GET_INFO_PGD);
			printf("pgd getinfo %d\n",ret);

     			ret = ioctl(fd,IOCTL_GET_INFO_VMAREA);
			printf("vmarea getinfo %d\n",ret);


 			int size = (0x1<<12) * 4096;
			addr =  mmap((void*)0x00000106fffff000,size,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED,0,0);
			printf("mmapping returned addr %p\n",addr);
			//end = start+size;

			char *ptr = (char *)addr;
		//	ptr[0]='a';
		//	ptr[1] = ptr[0];

			end = &(ptr[size-1]);

			for( ; addr <= end; ){
					
				ptr = (char *)addr;
				ptr[0] = 'a';
				info.ds = -1;
				info.addr = addr;
     				ret = ioctl(fd,IOCTL_SYNC_MASTER,&info);
				printf("pgd sync master %d\n",ret);
				addr =(void*)(((ulong) addr) + 0x0000000000200000);

			}
     			ret = ioctl(fd,IOCTL_GET_INFO_PGD);
			printf("pgd getinfo %d\n",ret);

     			ret = ioctl(fd,IOCTL_GET_INFO_VMAREA);
			printf("vmarea getinfo %d\n",ret);

     			ret = ioctl(fd,IOCTL_TRACE_VMAREA,(void*)ptr);
			printf("vmarea trace %d\n",ret);

	}


	if (argc == 2 && strcmp(argv[1],"dommapalljob") == 0){


			signal(SIGSEGV,handler);
			ret = pthread_create(&tid,NULL,cross_checker,NULL);
			printf("phtread create returned %d\n",ret);

			ret = ioctl(fd, IOCTL_INIT_PGD);
			printf("init pgd is %d\n",ret);
			fflush(stdout);

//goto skip;
			pgd_ds = ioctl(fd, IOCTL_GET_PGD);  //ioctl call 
			printf("pgd descriptor is %d\n",pgd_ds);
			fflush(stdout);
			


			ret = ioctl(fd,IOCTL_INSTALL_PGD,pgd_ds);
			printf("pgd installing returned %d\n",ret);
			fflush(stdout);
			
//			sleep(1);

//     			ret = ioctl(fd,IOCTL_UNINSTALL_PGD,pgd_ds);
//			printf("pgd uninstalling returned %d\n",ret);
//			fflush(stdout);

//skip:
     			ret = ioctl(fd,IOCTL_GET_INFO_PGD);
			printf("pgd getinfo %d\n",ret);
			fflush(stdout);

     			ret = ioctl(fd,IOCTL_GET_INFO_VMAREA);
			printf("vmarea getinfo %d\n",ret);
			fflush(stdout);

			addr =  mmap((void*)0x0000010000000000,4096,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED,0,0);
			printf("mmapping returned addr %p\n",addr);
			fflush(stdout);

			char *ptr = (char *)addr;
			ptr[0]='a';


		//for (i=0;i<4096;i++) buff[i]='\0';

//			addr =  mmap((void*)0x00000ff000000000,4096,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED,0,0);
	//		addr =  mmap(0x0000000f00000000,4096,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,0,0);
	//		perror("");
	//		printf("mmapping returned addr %p\n",addr);


		//	ret = munmap(addr,4096);
		//	printf("unmapping returned %d\n",ret);

//return;

     			ret = ioctl(fd,IOCTL_GET_INFO_PGD);
			printf("pgd getinfo %d\n",ret);
			fflush(stdout);

     			ret = ioctl(fd,IOCTL_GET_INFO_VMAREA);
			printf("vmarea getinfo %d\n",ret);
			fflush(stdout);

			//pause();

			sleep(3);

     			ret = ioctl(fd,IOCTL_UNINSTALL_PGD,pgd_ds);
			printf("pgd uninstalling returned %d\n",ret);
			fflush(stdout);

    			ret = ioctl(fd,IOCTL_RELEASE_PGD,pgd_ds);
			printf("pgd release returned %d\n",ret);
			fflush(stdout);

// now things are restored 
     			ret = ioctl(fd,IOCTL_GET_INFO_PGD);
			printf("pgd getinfo %d\n",ret);
			fflush(stdout);

     			ret = ioctl(fd,IOCTL_GET_INFO_VMAREA);
			printf("vmarea getinfo %d\n",ret);
			fflush(stdout);

			ptr[0]='a';

     			ret = ioctl(fd,IOCTL_GET_INFO_PGD);
			printf("pgd getinfo %d\n",ret);
			fflush(stdout);

     			ret = ioctl(fd,IOCTL_GET_INFO_VMAREA);
			printf("vmarea getinfo %d\n",ret);
			fflush(stdout);

			exit(0);

//			pause();
	}



	if (argc == 2 && strcmp(argv[1],"dommapandpagesall") == 0){


			signal(SIGSEGV,handler);
			signal(SIGINT,handler);
//goto skip;

//skip:
/*
     			ret = ioctl(fd,IOCTL_GET_INFO_PGD);
			printf("pgd getinfo %d\n",ret);

     			ret = ioctl(fd,IOCTL_GET_INFO_VMAREA);
			printf("vmarea getinfo %d\n",ret);
*/

			signal(SIGSEGV,handler);
			ret = pthread_create(&tid,NULL,cross_checker,NULL);
			printf("phtread create returned %d\n",ret);

			ret = ioctl(fd, IOCTL_INIT_PGD);
			printf("init pgd is %d\n",ret);
			fflush(stdout);

//goto skip;
			pgd_ds = ioctl(fd, IOCTL_GET_PGD);  //ioctl call 
			printf("pgd descriptor is %d\n",pgd_ds);
			fflush(stdout);

 			int size = (0x1<<12) * 4096;
			addr =  mmap((void*)0x00000106fffff000,size,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED,0,0);
			printf("mmapping returned addr %p\n",addr);
			//end = start+size;

			char *ptr = (char *)addr;
		//	ptr[0]='a';
		//	ptr[1] = ptr[0];

			end = &(ptr[size-1]);
			addr1 = addr;

			for( ; addr <= end; ){
					
				ptr = (char *)addr;
				ptr[0] = 'a';
				info.ds = pgd_ds;
				info.addr = addr;
     				ret = ioctl(fd,IOCTL_SYNC_MASTER,&info);
				printf("pgd sync master %d\n",ret);
				addr =(void*)(((ulong) addr) + 0x0000000000200000);

			}
			addr = addr1;

			sleep(3);

     			ret = ioctl(fd,IOCTL_UNINSTALL_PGD,pgd_ds);
			printf("pgd uninstalling returned %d\n",ret);
			fflush(stdout);

    			ret = ioctl(fd,IOCTL_RELEASE_PGD,pgd_ds);
			printf("pgd release returned %d\n",ret);
			fflush(stdout);
     			ret = ioctl(fd,IOCTL_GET_INFO_PGD);
			printf("pgd getinfo %d\n",ret);

     			ret = ioctl(fd,IOCTL_GET_INFO_VMAREA);
			printf("vmarea getinfo %d\n",ret);

     			ret = ioctl(fd,IOCTL_TRACE_VMAREA,(void*)ptr);
			printf("vmarea trace %d\n",ret);

	}


	if (argc == 2 && strcmp(argv[1],"inspectmm") == 0){



			ret = ioctl(fd, IOCTL_INIT_PGD);
			printf("init pgd is %d\n",ret);
			fflush(stdout);

//goto skip;
			pgd_ds = ioctl(fd, IOCTL_GET_PGD);  //ioctl call 
			printf("pgd descriptor is %d\n",pgd_ds);
			fflush(stdout);
			


			ret = ioctl(fd,IOCTL_INSTALL_PGD,pgd_ds);
			printf("pgd installing returned %d\n",ret);
			fflush(stdout);
			
     			ret = ioctl(fd,IOCTL_GET_INFO_PGD);
			printf("pgd getinfo %d\n",ret);

			sleep(3);

     			ret = ioctl(fd,IOCTL_GET_INFO_PGD);
			printf("pgd getinfo %d\n",ret);

     			ret = ioctl(fd,IOCTL_UNINSTALL_PGD,pgd_ds);
			printf("pgd uninstalling returned %d\n",ret);
			fflush(stdout);

	}


	if (argc == 2 && strcmp(argv[1],"vmareainfo") == 0){
     			ret = ioctl(fd,IOCTL_GET_INFO_VMAREA);
			printf("vmarea getinfo %d\n",ret);
	}

	if (argc == 2 && strcmp(argv[1],"changeview") == 0){
	//pgd_ds = ioctl(fd, IOCTL_INIT_PGD);  //ioctl call 
			pgd_ds = ioctl(fd, IOCTL_GET_PGD);  //ioctl call 
			printf("pgd descriptor is %d\n",pgd_ds);
			info.ds = -1;
			info.addr = 0x00008f8000000000;
		//	info.mapped_processes = 512;
			scanf("%d",&info.mapped_processes);
     			ret = ioctl(fd,IOCTL_CHANGE_VIEW,&info);
			pgd_ds = ioctl(fd, IOCTL_RELEASE_PGD, pgd_ds);  //ioctl call 
	}


	if (argc == 2 && strcmp(argv[1],"changevmmode") == 0){
	//pgd_ds = ioctl(fd, IOCTL_INIT_PGD);  //ioctl call 
//			pgd_ds = ioctl(fd, IOCTL_REGISTER_THREAD);  //ioctl call 

			pgd_ds = ioctl(fd, IOCTL_SET_ANCESTOR_PGD);  //ioctl call 
			printf("set ancestor is %d\n",pgd_ds);


     			ret = ioctl(fd,IOCTL_GET_INFO_VMAREA);
			printf("vmarea getinfo %d\n",ret);

			info.ds = -1;
			info.addr = 0x0000008000000000;
	//		info.callback = 0x000000000040255c;
	//		info.callback =	0x0000000000400a74;
			callback_function = my_print;
			info.callback =	callback_function;
			
		//	info.mapped_processes = 512;
			scanf("%d",&info.mapped_processes);
			int num_mmap = info.mapped_processes * 2;
			char * addr;
			char* addr1;

			addr = info.addr;
			addr1 = (char*)addr;
			for(i=0;i<num_mmap;i++){
 			int size = 256 * 512 * 4096;
			addr =  mmap((void*)addr,size,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED,0,0);
			addr[0] = 'x';
			addr[1] = addr[0];
			addr = addr+size;
			printf("mmapping returned addr %p\n",addr);
			}
/*
 			size = info.mapped_processes * 512 * 4096;
			addr =  mmap((void*)info.addr+size,size,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED,0,0);
			printf("mmapping returned addr %p\n",addr);
*/

     			ret = ioctl(fd,IOCTL_GET_INFO_VMAREA);
			printf("vmarea getinfo %d\n",ret);
			ioctl(fd,IOCTL_TRACE_VMAREA,(void*)addr1);

     			ret = ioctl(fd,IOCTL_SET_VM_RANGE,&info);

			sleep(1);
		for (i=0;i<NUM_THREADS;i++){		
			ret = pthread_create(&tid_id[i],NULL,root_sim_thread,NULL);
			printf("pthread create (root_sim thread spawning) returned %d\n",ret);
		}
		for (i=0;i<NUM_THREADS;i++){		
			ret = pthread_join(tid_id[i],dummy);
		}

/*
			ret = pthread_create(&tid,NULL,root_sim_thread,NULL);
			printf("pthread create (root_sim thread spawning) returned %d\n",ret);

			ret = pthread_create(&tid,NULL,root_sim_thread,NULL);
			printf("pthread create (root_sim thread spawning) returned %d\n",ret);

			ret = pthread_create(&tid,NULL,root_sim_thread,NULL);
			printf("pthread create (root_sim thread spawning) returned %d\n",ret);
*/
//			addr1[0] = 'x';
//			addr1[1] = addr1[0];
//     			ret = ioctl(fd,IOCTL_GET_INFO_VMAREA);
//			printf("vmarea getinfo %d\n",ret);
//			ioctl(fd,IOCTL_TRACE_VMAREA,(void*)addr1);
//     			ret = ioctl(fd,IOCTL_CHANGE_VIEW);
//			ioctl(fd,IOCTL_TRACE_VMAREA,(void*)addr1);

//			pgd_ds = ioctl(fd, IOCTL_DEREGISTER_THREAD);  //ioctl call 
		//	sleep(7);
     			ret = ioctl(fd,IOCTL_SET_THREADS);
	}

	if (argc == 2 && strcmp(argv[1],"check") == 0){


			info.ds = -1;
			info.addr = 0x0000008000000000;
		//	info.mapped_processes = 512;
			scanf("%d",&info.mapped_processes);
			int num_mmap = info.mapped_processes * 2;
			char * addr;
			char* addr1;

			addr = info.addr;
			addr1 = (char*)addr;
/*
*/


     			ret = ioctl(fd,IOCTL_SET_VM_RANGE,&info);
     			ret = ioctl(fd,IOCTL_CHANGE_VIEW);

	}

	close(fd);
}
