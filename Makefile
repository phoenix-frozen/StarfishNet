.PHONY: all clean

CFLAGS += "-std=gnu99" -DMAC_DEBUG

all: parenttest childtest

clean:
	rm -f *.o
	rm -f parenttest childtest

parenttest: parenttest.o mac802154.o
childtest: childtest.o sn_core.o mac802154.o
