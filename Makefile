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

all: parenttest childtest

clean:
	rm -f $(OBJECTS) Makefile.deps parenttest childtest

Makefile.deps: $(SOURCES)
	gcc -MM $(SOURCES) >$@

parenttest: parenttest.o $(OBJECTS)
childtest: childtest.o $(OBJECTS)

-include Makefile.deps
