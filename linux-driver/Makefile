CC ?= gcc
CFLAGS ?= -Wall -Wextra -O2 -Iinclude $(shell pkg-config --cflags libusb-1.0)
LIBS ?= $(shell pkg-config --libs libusb-1.0)

TARGET = fpc_disum_tool

all: $(TARGET)

$(TARGET): src/fpc_disum_tool.c include/fpc_protocol.h
	$(CC) $(CFLAGS) -o $@ src/fpc_disum_tool.c $(LIBS)

clean:
	rm -f $(TARGET) *.pgm

install-udev:
	sudo cp udev/70-libfprint-2-fpc2040.rules /etc/udev/rules.d/
	sudo udevadm control --reload-rules
	sudo udevadm trigger

.PHONY: all clean install-udev
