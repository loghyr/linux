# SPDX-License-Identifier: GPL-2.0-only
#
# Demonstrator tools for the nfsd Flex Files v2 prototype authority gate.
# Nothing in the kernel build refers to these; build them explicitly, and
# only for a disposable test machine.
#
CFLAGS ?= -Wall -Wextra -O2
# Point KHDR at a kernel build directory that has had "make headers_install"
# run in it, so these tools use this tree's uapi definitions and not the
# host's.
KHDR ?= ../../../usr/include
CFLAGS += -I$(KHDR)

PROGS = ffv2-proto-ctl ffv2-live-probe

all: $(PROGS)

ffv2-proto-ctl: ffv2-proto-ctl.c
	$(CC) $(CFLAGS) -o $@ $<

ffv2-live-probe: ffv2-live-probe.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(PROGS)

.PHONY: all clean
