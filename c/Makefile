TARGET=bin/ecdsa-keys

CC=gcc -std=gnu99 -D_GNU_SOURCE
LINKER=gcc -std=gnu99 -D_GNU_SOURCE

CFLAGS=-g -Wall
CFLAGS += -Iinclude

LIBS=-lm -lpthread
LIBS += -lgmp

# libsecp256k1
CRYPTO_INCLUDE=$(shell pkg-config --cflags libsecp256k1)
CRYPTO_LIBS=$(shell pkg-config --libs libsecp256k1)

BASE_SRC=$(wildcard base/*.c)
BASE_OBJ=$(BASE_SRC:base/%.c=base/%.o)

ifeq ($USE_OPENSSL,1)
	CRYPTO_INCLUDE=$(shell pkg-config --cflags openssl)
	CRYPTO_LIBS=$(shell pkg-config --libs openssl)
endif


SOURCES := $(wildcard src/*.c)
OBJECTS := $(SOURCES:src/%.c=obj/%.o)

all: $(TARGET)

$(TARGET): $(OBJECTS) $(BASE_OBJ)
	@test -e bin || mkdir bin
	$(LINKER) -o $@ $(OBJECTS) $(BASE_OBJ) $(CRYPTO_LIBS) $(LIBS)


$(OBJECTS): obj/%.o : src/%.c
	@test -e obj || mkdir -p obj/base
	$(CC) -o $@ -c $< $(CFLAGS)
	
$(BASE_OBJ): %.o : %.c
	$(CC) -o $@ -c $< $(CFLAGS)
	
.PHONY: clean
clean:
	rm -rf obj/*.o $(TARGET)


	
