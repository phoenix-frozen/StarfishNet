TARGET = libstarfishnet

SRCS = $(wildcard src/*.c)
OBJS = $(SRCS:.c=.o)
DEPS = $(SRCS:.c=.d)

LIB_DIRS = $(filter-out %.a,$(wildcard lib/*))
LIBS = $(LIB_DIRS:lib/%=lib/lib%.a)

TEST_SRC = $(wildcard test/*.c)
TEST_BIN = $(TEST_SRC:.c=)

.PHONY: all clean deps cscope

CC = gcc
CFLAGS += -I./include
CFLAGS += $(LIB_DIRS:%=-I%/include)
CFLAGS += $(LIB_DIRS:%=-I%/inc)
CFLAGS += -std=gnu99
CFLAGS += -DSN_DEBUG
#CFLAGS += -DSN_DEBUG_LEVEL=4
#CFLAGS += -DMAC_DEBUG
#CFLAGS += -DNDEBUG

all: $(TARGET).a $(LIBS) $(TEST_BIN)

deps: $(DEPS)

clean:
	$(RM) $(OBJS) $(DEPS) $(TEST_BIN) $(TARGET).a $(LIBS)

%.d: %.c
	gcc -MM -I./include $< -o $@

include $(DEPS)

#generate static library
$(TARGET).a: $(OBJS)
	$(AR) r $@ $(OBJS)
	$(AR) s $@

#TODO: generate shared library

#make sure test binaries link against and depend on libstarfishnet and dependent libraries
$(TEST_BIN): $(TARGET).a $(LIBS)

#build dependency libraries by recursive make invocation, and link the generated library (wherever it is) into lib/libname.a
# (also make sure they don't inherit our CFLAGS)
lib/lib%.a: CFLAGS = 
lib/lib%.a: lib/%
	$(MAKE) -C $<
	cd lib && ln -sf `find \`basename $<\` -name \`basename $@\`` `basename $@`

#generate cscope database
cscope: cscope.out cscope.in.out cscope.po.out
cscope.out cscope.in.out cscope.po.out: $(SRCS)
	cscope -b -q -R

.SECONDEXPANSION:

#build test binaries (uses second-expansion to fire Make's implicit rule for building C programs)
$(TEST_BIN): $$@.c

