.PHONY: all clean

SOURCES = sn_core.c sn_table.c mac802154.c
OBJECTS = $(SOURCES:.c=.o)
CC = gcc

#TODO: generate shared and static libraries

CFLAGS += -std=gnu99
CFLAGS += -DSN_DEBUG
#CFLAGS += -DSN_DEBUG_LEVEL=4
#CFLAGS += -DMAC_DEBUG
#CFLAGS += -DNDEBUG
LDLIBS += -lz

all: parenttest childtest

clean:
	rm -f *.o
	rm -f parenttest childtest

parenttest: parenttest.o $(OBJECTS)
childtest: childtest.o $(OBJECTS)
