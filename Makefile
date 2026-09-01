PREFIX ?= /usr/local
DESTDIR ?=
BINDIR := $(DESTDIR)$(PREFIX)/bin
DATADIR := $(DESTDIR)$(PREFIX)/share
DESKTOPDIR := $(DATADIR)/applications
ICONDIR := $(DATADIR)/icons/hicolor/scalable/apps

TARGET := omapass
BUILD_DIR := build
TEST_BUILD_DIR := build-tests

.PHONY: all build test install uninstall clean distclean

all: build

build:
	./bin/build

test:
	./bin/test

install: build
	install -Dm755 $(BUILD_DIR)/$(TARGET) $(BINDIR)/$(TARGET)
	install -Dm755 $(BUILD_DIR)/keepassxc-cli $(BINDIR)/keepassxc-cli
	install -Dm644 $(TARGET).desktop $(DESKTOPDIR)/$(TARGET).desktop
	install -Dm644 icons/$(TARGET).svg $(ICONDIR)/$(TARGET).svg
	@echo "omapass instalado em $(BINDIR)/$(TARGET)"

uninstall:
	rm -f $(BINDIR)/$(TARGET)
	rm -f $(BINDIR)/keepassxc-cli
	rm -f $(DESKTOPDIR)/$(TARGET).desktop
	rm -f $(ICONDIR)/$(TARGET).svg
	@echo "omapass removido de $(BINDIR)/$(TARGET)"

clean:
	rm -rf $(BUILD_DIR) $(TEST_BUILD_DIR)

distclean: clean
