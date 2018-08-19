TARGET=bin/lightning

CC=gcc -std=gnu99 -D_GNU_SOURCE
LINKER=gcc -std=gnu99 -D_GNU_SOURCE
AR=ar

DEBUG=-Wall

DEBUG_MODE ?= 1

ifeq ($(DEBUG_MODE),1)
	DEBUG += -g
endif


INCLUDE=-Iinclude -Isrc

CFLAGS=$(DEBUG) $(OPTIMIZE) $(INCLUDE)
CFLAGS += $(shell pkg-config --cflags libsecp256k1 json-c)

LIBS=-lm -ldb -lpthread -lcrypto -lssl -lgmp
LIBS += $(shell pkg-config --libs libsecp256k1 json-c)

# sources
SRC_DIR=src
OBJ_DIR=obj
BIN_DIR=bin

SOURCES := $(wildcard $(SRC_DIR)/*.c)
OBJECTS := $(SOURCES:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)

BASE_SRC_DIR=base
BASE_OBJ_DIR=obj/base
BASE_SOURCES := $(wildcard $(BASE_SRC_DIR)/*.c)
BASE_OBJECTS := $(BASE_SOURCES:$(BASE_SRC_DIR)/%.c=$(BASE_OBJ_DIR)/%.o)
BASE_LIB := lib/base.a


all: do_init $(TARGET)

$(TARGET): $(OBJECTS) $(BASE_LIB)
	$(LINKER) -o $@ $(OBJECTS) $(BASE_LIB) $(LIBS)

$(OBJECTS): $(OBJ_DIR)/%.o : $(SRC_DIR)/%.c
	$(CC) -o $@ -c $< $(CFLAGS)

$(BASE_LIB): $(BASE_OBJECTS)
	$(AR) crf $@ $(BASE_OBJECTS)

$(BASE_OBJECTS): $(BASE_OBJ_DIR)/%.o : $(BASE_SRC_DIR)/%.c
	$(CC) -o $@ -c $< $(CFLAGS)

.PHONY: do_init clean test
do_init:
	mkdir -p obj lib bin data log conf test tmp obj/base

clean:
	rm -rf obj/* $(TARGET)
	
test: bin/tx 

bin/tx: $(BASE_LIB) src/tx.c
	$(LINKER) -o $@ -D_STAND_ALONE $(CFLAGS) src/tx.c $(BASE_LIB) $(LIBS) 
	
