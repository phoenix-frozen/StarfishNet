.PHONY: all clean

SOURCES = sn_core.c sn_table.c mac802154.c
OBJECTS = $(SOURCES:.c=.o)

#TODO: generate shared and static libraries

CFLAGS += "-std=gnu99" -DMAC_DEBUG

all: parenttest childtest

clean:
	rm -f *.o
	rm -f parenttest childtest

parenttest: parenttest.o $(OBJECTS)
childtest: childtest.o $(OBJECTS)
