CONFIG_OPTPROBES=y
CONFIG_PREEMPT=y
CONFIG_OPTPROBES=y
CONFIG_MODULE_UNLOAD=y
CONFIG_MODULES=y
CONFIG_KALLSYMS=y
CONFIG_KALLSYMS_ALL=y
CONFIG_DEBUG_INFO=y

CONFIG_MODULE_FORCE_LOAD=y
CONFIG_MODULE_SIG=n
CONFIG_MODULE_SIG_ALL=n

obj-m += extractModule.o
zt-objs := extractModule.o
BUILD_FLAGS=-Wno-unused-function

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) EXTRA_CFLAGS="$(BUILD_FLAGS)" modules

debug: BUILD_FLAGS+=-DDEBUG
debug:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) EXTRA_CFLAGS="$(BUILD_FLAGS)" modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm -f Module.markers modules.order
