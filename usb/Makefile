CC = avr-gcc
CFLAGS = -Wall -Os -Iusbdrv -mmcu=attiny2313 -std=c99
OBJFLAGS = -j .text -j .data -O ihex
DUDEFLAGS = -p attiny2313 -c avrisp -P /dev/ttyACM0 -b 19200

OBJECTS = usbdrv/usbdrv.o usbdrv/oddebug.o usbdrv/usbdrvasm.o main.o

all: main.hex 

flash: main.hex
	avrdude $(DUDEFLAGS) -U flash:w:$<

clean:
	$(RM) *.o *.hex *.elf usbdrv/*.o

%.hex: %.elf
	avr-objcopy $(OBJFLAGS) $< $@

main.elf: $(OBJECTS)
	$(CC) $(CFLAGS) $(OBJECTS) -o $@

$(OBJECTS): usbdrv/usbconfig.h

%.o: %.c	
	$(CC) $(CFLAGS) -c $< -o $@

%.o: %.S
	$(CC) $(CFLAGS) -x assembler-with-cpp -c $< -o $@

fuse:
	avrdude $(DUDEFLAGS) -U lfuse:w:0xEF:m -U hfuse:w:0xDF:m -U efuse:w:0xFF:m 
