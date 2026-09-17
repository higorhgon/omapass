PREFIX ?= /usr/local
DESTDIR ?=
BINDIR := $(DESTDIR)$(PREFIX)/bin
DATADIR := $(DESTDIR)$(PREFIX)/share
DESKTOPDIR := $(DATADIR)/applications
ICONDIR := $(DATADIR)/icons/hicolor/scalable/apps
WORDLISTDIR := $(DATADIR)/omapass/wordlists

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
	install -Dm644 vendor/keepassxc/share/wordlists/eff_large.wordlist $(WORDLISTDIR)/eff_large.wordlist
	install -Dm644 wordlists/pt-BR.wordlist $(WORDLISTDIR)/pt-BR.wordlist
	@echo "omapass instalado em $(BINDIR)/$(TARGET)"

uninstall:
	rm -f $(BINDIR)/$(TARGET)
	rm -f $(BINDIR)/keepassxc-cli
	rm -f $(DESKTOPDIR)/$(TARGET).desktop
	rm -f $(ICONDIR)/$(TARGET).svg
	rm -f $(WORDLISTDIR)/eff_large.wordlist
	rm -f $(WORDLISTDIR)/pt-BR.wordlist
	@echo "omapass removido de $(BINDIR)/$(TARGET)"

clean:
	rm -rf $(BUILD_DIR) $(TEST_BUILD_DIR)

distclean: clean
