PS5_HOST ?= ps5
PS5_PORT ?= 9021

ifndef PS5_PAYLOAD_SDK
    PS5_PAYLOAD_SDK ?= /opt/ps5-payload-sdk
endif

include $(PS5_PAYLOAD_SDK)/toolchain/prospero.mk


ELF := ps5-nanodns.elf
ELF_DEBUG := $(ELF).debug

SRCS := main.c dns.c web.c cfg.c utils.c
OBJS := $(SRCS:.c=.o)

CFLAGS := -Wall -Wextra -Werror -O2 -g -std=c11
LDLIBS := -lSceNet

all: $(ELF)

$(ELF): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)
	cp $@ $(ELF_DEBUG)
	$(STRIP) --strip-debug $@

clean:
	rm -f $(ELF) $(ELF_DEBUG) $(OBJS)

test: $(ELF)
	$(PS5_DEPLOY) -h $(PS5_HOST) -p $(PS5_PORT) $^

debug: $(ELF)
	gdb-multiarch \
	-ex "set architecture i386:x86-64" \
	-ex "target extended-remote $(PS5_HOST):2159" \
	-ex "file $(ELF_DEBUG)" \
	-ex "remote put $(ELF) /data/$(ELF)" \
	-ex "set remote exec-file /data/$(ELF)" \
	-ex "start"
