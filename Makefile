all: hal-init-wedge emu-hal

emu-hal: emu-hal.c
	gcc -Wall emu-hal.c -lunicorn -lpthread -o emu-hal

hal-init-wedge: hal-init-wedge.S
	arm-linux-gnueabi-as hal-init-wedge.S -o hal-init-wedge.o
	objcopy --only-section=.text hal-init-wedge.o -O binary hal-init-wedge

clean:
	rm -f emu-hal hal-init-wedge.o hal-init-wedge
