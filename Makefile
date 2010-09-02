obj-m := sendsig.o
KDIR  := /lib/modules/$(shell uname -r)/build
PWD   := $(shell pwd)
DEPMOD:=$(shell which depmod)
# possible bug: maybe this will work only on debian based systems
SYSMAP:= /boot/System.map-$(shell uname -r)

default:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules 

install:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules_install
	$(DEPMOD) -ae -F $(SYSMAP)

clean:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) clean