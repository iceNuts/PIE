#
# Makefile for Process Integrity Evaluator
# Authored By Bill Zeng
#

obj-m += pie.o 

pie-objs := pie_tpm.o pie_cache.o


all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean