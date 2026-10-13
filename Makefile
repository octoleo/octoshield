SHELL := /bin/bash
CC ?= cc
CFLAGS ?= -O2
CPPFLAGS ?= -D_FORTIFY_SOURCE=2
WARNINGS := -std=c11 -Wall -Wextra -Werror -pedantic
HARDENING := -fstack-protector-strong -fPIE -pie -Wl,-z,relro,-z,now
SHELL_FILES := src/octoshield src/octoshield-helper src/status-daemon $(wildcard debian/octoshield.postinst debian/octoshield.prerm debian/octoshield.postrm scripts/*.sh) $(shell find src tests -type f \( -name '*.sh' -o -name '*.bats' \) | sort)
UI_PACKAGES := gtk4 libadwaita-1 json-glib-1.0 gio-2.0
SESSION_PACKAGES := gio-2.0 json-glib-1.0
CLI_FILES := $(shell bash -c 'source src/lib/install.sh; install::files')
DESTDIR ?=

.PHONY: all gui ui-test ui-display-test test-gui check lint format test sanitize install package clean
all: build/octoshield-monitor

build/octoshield-monitor: src/monitor.c
	mkdir -p build
	$(CC) $(CPPFLAGS) $(CFLAGS) $(WARNINGS) $(HARDENING) $< $(LDFLAGS) -o $@

gui: build/octoshield-gtk build/octoshield-session

build/octoshield-session: src/session-broker.c src/ui/protocol.c src/ui/protocol.h
	mkdir -p build
	$(CC) $(CPPFLAGS) $(CFLAGS) $(WARNINGS) $(HARDENING) $$(pkg-config --cflags $(SESSION_PACKAGES)) src/session-broker.c src/ui/protocol.c $(LDFLAGS) -o $@ $$(pkg-config --libs $(SESSION_PACKAGES))

build/test-session: tests/session-broker.c src/session-broker.c src/ui/protocol.c src/ui/protocol.h
	mkdir -p build
	$(CC) $(CPPFLAGS) $(CFLAGS) $(WARNINGS) $(HARDENING) $$(pkg-config --cflags $(SESSION_PACKAGES)) tests/session-broker.c src/ui/protocol.c $(LDFLAGS) -o $@ $$(pkg-config --libs $(SESSION_PACKAGES))

build/octoshield-resources.c: data/branding/octoshield.gresource.xml data/branding/OctoShield-light.png data/branding/OctoShield-dark.png
	mkdir -p build
	glib-compile-resources --sourcedir=data/branding --generate-source --target=$@ $<

build/octoshield-resources.o: build/octoshield-resources.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $(WARNINGS) -Wno-overlength-strings -fPIE $$(pkg-config --cflags gio-2.0) -c $< -o $@

build/octoshield-gtk: src/ui/octoshield-gtk.c src/ui/protocol.c src/ui/protocol.h build/octoshield-resources.o
	mkdir -p build
	$(CC) $(CPPFLAGS) $(CFLAGS) $(WARNINGS) $(HARDENING) $$(pkg-config --cflags $(UI_PACKAGES)) src/ui/octoshield-gtk.c src/ui/protocol.c build/octoshield-resources.o $(LDFLAGS) -o $@ $$(pkg-config --libs $(UI_PACKAGES))

build/test-ui: tests/ui-test.c src/ui/protocol.c src/ui/protocol.h
	mkdir -p build
	$(CC) $(CPPFLAGS) $(CFLAGS) $(WARNINGS) $(HARDENING) -Isrc/ui $$(pkg-config --cflags glib-2.0 json-glib-1.0) tests/ui-test.c src/ui/protocol.c $(LDFLAGS) -o $@ $$(pkg-config --libs glib-2.0 json-glib-1.0)

ui-test test-gui: gui build/test-ui build/test-session
	build/test-ui
	build/test-session
	bats tests/gui/*.bats

build/test-ui-app: tests/ui-app-test.c src/ui/octoshield-gtk.c src/ui/protocol.c src/ui/protocol.h build/octoshield-resources.o
	mkdir -p build
	$(CC) $(CPPFLAGS) $(CFLAGS) $(WARNINGS) $(HARDENING) -Isrc/ui $$(pkg-config --cflags $(UI_PACKAGES)) tests/ui-app-test.c src/ui/protocol.c build/octoshield-resources.o $(LDFLAGS) -o $@ $$(pkg-config --libs $(UI_PACKAGES))

build/test-ui-lifecycle: tests/gui/lifecycle.c src/ui/octoshield-gtk.c src/ui/protocol.c src/ui/protocol.h build/octoshield-resources.o
	mkdir -p build
	$(CC) $(CPPFLAGS) $(CFLAGS) $(WARNINGS) $(HARDENING) -Isrc/ui $$(pkg-config --cflags $(UI_PACKAGES)) tests/gui/lifecycle.c src/ui/protocol.c build/octoshield-resources.o $(LDFLAGS) -o $@ $$(pkg-config --libs $(UI_PACKAGES))

ui-display-test: build/test-ui-app build/test-ui-lifecycle
	dbus-run-session -- xvfb-run -a env GTK_A11Y=none GSK_RENDERER=cairo OCTOSHIELD_TEST_SCREENSHOTS=1 build/test-ui-app
	dbus-run-session -- xvfb-run -a env GTK_A11Y=none GSK_RENDERER=cairo build/test-ui-lifecycle

lint:
	shellcheck -x -P SCRIPTDIR $(SHELL_FILES)
	shfmt -i 4 -ci -d $(SHELL_FILES)
	@for script in $(SHELL_FILES); do case "$$script" in *.bats) ;; *) bash -n "$$script" || exit ;; esac; done

format:
	shfmt -i 4 -ci -w $(SHELL_FILES)

test: all
	bats tests/*.bats
	bash tests/monitor.sh

check: lint test

# Staged package assembly only; installing with apt owns the system lifecycle.
install: all gui
	@test -n "$(DESTDIR)" || { echo 'Use make package or supply a staging DESTDIR.' >&2; exit 1; }
	@for file in $(CLI_FILES); do install -D -m 0644 "$$file" "$(DESTDIR)/usr/lib/octoshield/$$file"; done
	chmod 0755 "$(DESTDIR)/usr/lib/octoshield/src/octoshield" "$(DESTDIR)/usr/lib/octoshield/src/notify.sh" "$(DESTDIR)/usr/lib/octoshield/src/status-daemon"
	install -D -m 0755 build/octoshield-monitor "$(DESTDIR)/usr/lib/octoshield/bin/octoshield-monitor"
	install -D -m 0755 build/octoshield-gtk "$(DESTDIR)/usr/bin/octoshield-gtk"
	install -D -m 0755 src/octoshield-helper "$(DESTDIR)/usr/libexec/octoshield-helper"
	install -D -m 0755 build/octoshield-session "$(DESTDIR)/usr/libexec/octoshield-session"
	install -D -m 0755 src/usb-prompt.sh "$(DESTDIR)/usr/lib/octoshield/src/usb-prompt.sh"
	install -D -m 0644 systemd/octoshield-usb-agent.service "$(DESTDIR)/usr/lib/systemd/user/octoshield-usb-agent.service"
	sed -i 's@/usr/local/@/usr/@g' "$(DESTDIR)/usr/lib/systemd/user/octoshield-usb-agent.service"
	install -D -m 0644 data/io.vdm.OctoShield.UsbAgent.desktop "$(DESTDIR)/etc/xdg/autostart/io.vdm.OctoShield.UsbAgent.desktop"
	printf '%s\n' '#!/bin/bash' 'exec /usr/bin/bash /usr/lib/octoshield/src/octoshield "$$@"' >"$(DESTDIR)/usr/bin/octoshield"
	chmod 0755 "$(DESTDIR)/usr/bin/octoshield"
	@for unit in octoshield-monitor.service octoshield-notify.service octoshield-status.service; do sed 's@/usr/local/@/usr/@g' "systemd/$$unit" >"$(DESTDIR)/usr/lib/octoshield/systemd/$$unit"; done
	install -D -m 0644 "$(DESTDIR)/usr/lib/octoshield/systemd/octoshield-monitor.service" "$(DESTDIR)/usr/lib/systemd/system/octoshield-monitor.service"
	install -D -m 0644 "$(DESTDIR)/usr/lib/octoshield/systemd/octoshield-status.service" "$(DESTDIR)/usr/lib/systemd/system/octoshield-status.service"
	install -D -m 0644 "$(DESTDIR)/usr/lib/octoshield/systemd/octoshield-notify.service" "$(DESTDIR)/usr/lib/systemd/user/octoshield-notify.service"
	install -D -m 0644 data/io.vdm.OctoShield.desktop "$(DESTDIR)/usr/share/applications/io.vdm.OctoShield.desktop"
	install -D -m 0644 data/branding/OctoShield-light.png "$(DESTDIR)/usr/share/pixmaps/io.vdm.OctoShield.png"
	install -D -m 0644 data/branding/OctoShield-light.png "$(DESTDIR)/usr/share/octoshield/branding/OctoShield-light.png"
	install -D -m 0644 data/branding/OctoShield-dark.png "$(DESTDIR)/usr/share/octoshield/branding/OctoShield-dark.png"
	install -D -m 0644 data/io.vdm.OctoShield.metainfo.xml "$(DESTDIR)/usr/share/metainfo/io.vdm.OctoShield.metainfo.xml"
	install -D -m 0644 data/io.vdm.OctoShield.policy "$(DESTDIR)/usr/share/polkit-1/actions/io.vdm.OctoShield.policy"

package:
	dpkg-buildpackage -us -uc -b

sanitize:
	mkdir -p build
	$(CC) -O1 -g $(WARNINGS) -fsanitize=address,undefined -fno-omit-frame-pointer tests/monitor.c -o build/test-monitor-sanitize
	ASAN_OPTIONS=$${ASAN_OPTIONS:-detect_leaks=1} build/test-monitor-sanitize
	$(CC) -O1 -g $(WARNINGS) -fsanitize=address,undefined -fno-omit-frame-pointer $$(pkg-config --cflags $(SESSION_PACKAGES)) tests/session-broker.c src/ui/protocol.c -o build/test-session-sanitize $$(pkg-config --libs $(SESSION_PACKAGES))
	ASAN_OPTIONS=$${ASAN_OPTIONS:-detect_leaks=1} build/test-session-sanitize

clean:
	rm -rf build
