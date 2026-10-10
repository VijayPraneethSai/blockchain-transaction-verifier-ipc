CC ?= gcc
CFLAGS ?= -O2 -Wall -Wextra
VERIFIER_SRC = main.c

all: bin/verifier

bin/verifier: $(VERIFIER_SRC)
	@mkdir -p bin
	$(CC) $(CFLAGS) -o $@ $(VERIFIER_SRC)

bin/driver: tests/driver.c
	@mkdir -p bin
	$(CC) $(CFLAGS) -o $@ tests/driver.c

# random cases checked against an independent calculation (needs System V IPC, i.e. Linux)
test: bin/verifier bin/driver
	sh tests/run_tests.sh bin/verifier bin/driver

clean:
	rm -rf bin

.PHONY: all test clean
