#
# Makefile for Process Integrity Evaluator
# Authored By Bill Zeng
#

obj-m += pie.o 

pie-objs := pie_tpm.o pie_cache.o
