PS_HOST = ps5
PS_PORT = 9021

ifeq ($(PS_HOST),ps4)
    PS4_HOST = $(PS_HOST)
    PS4_PORT = $(PS_PORT)
    export PS4_PAYLOAD_SDK = /opt/ps4-payload-sdk
    include $(PS4_PAYLOAD_SDK)/toolchain/orbis.mk
ELF := ps4-nanodns.elf
CFLAGS := -DPS4_HOST
else # PS5
    PS5_HOST = $(PS_HOST)
    PS5_PORT = $(PS_PORT)
    export PS5_PAYLOAD_SDK = /opt/ps5-payload-sdk
    include $(PS5_PAYLOAD_SDK)/toolchain/prospero.mk
ELF := ps5-nanodns.elf
CFLAGS := -DPS5_HOST
endif

ELF_DEBUG := $(ELF).debug

SRCS := main.c dns.c web.c cfg.c utils.c fnmatch.c
OBJS := $(SRCS:.c=.o)

CFLAGS += -Wall -Werror -O2 -g -std=c11
LDLIBS := -lSceNet -lpthread

all: $(ELF)

$(ELF): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)
	cp $@ $(ELF_DEBUG)
	$(STRIP) --strip-debug $@

clean:
	rm -f $(ELF_DEBUG) $(OBJS) *.debug

distclean: clean
	rm -f *nanodns.elf

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
