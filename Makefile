CC ?= gcc
CFLAGS ?= -std=c11 -Wall -Wextra -Wpedantic
LDLIBS ?= -lseccomp

PROGRAMS = sysjail compute_allowed compute_file_attempt \
	network_allowed network_attempt filesystem_read filesystem_mutation

.PHONY: all clean

all: $(PROGRAMS)

sysjail: sysjail.c
	$(CC) $(CFLAGS) $< -o $@ $(LDLIBS)

compute_allowed: compute_allowed.c
	$(CC) $(CFLAGS) $< -o $@ $(LDLIBS)

compute_file_attempt: compute_file_attempt.c
	$(CC) $(CFLAGS) $< -o $@ $(LDLIBS)

network_allowed: network_allowed.c
	$(CC) $(CFLAGS) $< -o $@ $(LDLIBS)

network_attempt: network_attempt.c
	$(CC) $(CFLAGS) $< -o $@ $(LDLIBS)

filesystem_read: filesystem_read.c
	$(CC) $(CFLAGS) $< -o $@ $(LDLIBS)

filesystem_mutation: filesystem_mutation.c
	$(CC) $(CFLAGS) $< -o $@ $(LDLIBS)

clean:
	rm -f $(PROGRAMS) blocked_mkdir allowed_program
