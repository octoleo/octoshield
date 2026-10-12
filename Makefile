SHELL := /bin/bash
CC ?= cc
CFLAGS ?= -O2
WARNINGS := -std=c11 -Wall -Wextra -Werror -pedantic
HARDENING := -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE -pie -Wl,-z,relro,-z,now
SHELL_FILES := src/octoshield $(shell find src tests -type f \( -name '*.sh' -o -name '*.bats' \) | sort)

.PHONY: all check lint format test sanitize clean
all: build/octoshield-monitor

build/octoshield-monitor: src/monitor.c
	mkdir -p build
	$(CC) $(CFLAGS) $(WARNINGS) $(HARDENING) $< -o $@

lint:
	shellcheck -x -P SCRIPTDIR $(SHELL_FILES)
	shfmt -i 4 -ci -d $(SHELL_FILES)
	@for script in src/octoshield $$(find src tests -type f -name '*.sh'); do bash -n "$$script" || exit; done

format:
	shfmt -i 4 -ci -w $(SHELL_FILES)

test: all
	bats tests/*.bats
	bash tests/monitor.sh

check: lint test

sanitize:
	mkdir -p build
	$(CC) -O1 -g $(WARNINGS) -fsanitize=address,undefined -fno-omit-frame-pointer tests/monitor.c -o build/test-monitor-sanitize
	ASAN_OPTIONS=$${ASAN_OPTIONS:-detect_leaks=1} build/test-monitor-sanitize

clean:
	rm -rf build
