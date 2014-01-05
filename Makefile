.PHONY: all clean

CFLAGS += "-std=gnu99" -DMAC_DEBUG

all: testbin network_test

clean:
	rm -f *.o
	rm -f testbin network_test

testbin: testbin.o mac-chardev.o
network_test: network_test.o network.o mac-chardev.o
