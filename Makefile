obj-m += act_trproxy.o
# adjust this to your location
GIT_SHA1 := $(shell git rev-parse HEAD)
KDIR  := $(HOME)/linux
MSRC  := $(HOME)/act-trproxy
ccflags-y := -I$(MSRC)/myinclude -I$(MSRC)/myinclude/uapi -DGIT_SHA1=\"$(GIT_SHA1)\" -Wno-error=date-time -DDEBUG

default:
	$(MAKE) -C $(KDIR) M=$(MSRC) modules
clean:
	$(MAKE) -C $(KDIR) M=$(MSRC) clean
