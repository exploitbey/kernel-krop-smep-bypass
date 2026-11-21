obj-m += rop.o

# -fno-stack-protector : stack canary'yi devre dışı bırak
# -D_FORTIFY_SOURCE=0  : fortify source kontrollerini kapat
# -g -Og               : debug sembolleri ile derle (offset bulmak için)
ccflags-y := -fno-stack-protector -D_FORTIFY_SOURCE=0 -g -Og

all:
	make -b -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -b -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
