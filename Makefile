CC ?= gcc
CLANG ?= clang
CFLAGS ?= -Wall -O2 -Isrc

all: xdns-ctl xdns_bpf.o

xdns-ctl: src/xdns_ctl.c src/xdns_bpf.h src/xdns_hash.h
	$(CC) $(CFLAGS) $< -o $@

xdns_bpf.o: src/xdns_bpf.c src/xdns_bpf.h
	$(CLANG) -target bpf -O2 -g -Wall -Isrc -I/usr/include -c $< -o $@

clean:
	rm -f xdns-ctl xdns_bpf.o

.PHONY: all clean
