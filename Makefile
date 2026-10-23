CC ?= gcc
CFLAGS ?= -std=c11 -Wall -Wextra -Wpedantic
LDLIBS ?= -lseccomp

PROGRAMS = sysjail blocked_mkdir allowed_program

.PHONY: all clean

all: $(PROGRAMS)

sysjail: sysjail.c
	$(CC) $(CFLAGS) $< -o $@ $(LDLIBS)

blocked_mkdir: blocked_mkdir.c
	$(CC) $(CFLAGS) $< -o $@ $(LDLIBS)

allowed_program: allowed_program.c
	$(CC) $(CFLAGS) $< -o $@ $(LDLIBS)

clean:
	rm -f $(PROGRAMS)
