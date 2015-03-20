obj-m += ktblmgr.o
ktblmgr-objs = ktblmgr1.o tracking_accesses.o
KVERSION = $(shell uname -r)
all:
	make -C /lib/modules/$(KVERSION)/build M=$(PWD) modules
clean:
	make -C /lib/modules/$(KVERSION)/build M=$(PWD) clean
