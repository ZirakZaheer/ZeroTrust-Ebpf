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
