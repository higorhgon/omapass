PREFIX ?= /usr/local
DESTDIR ?=
BINDIR := $(DESTDIR)$(PREFIX)/bin

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
	@echo "omapass instalado em $(BINDIR)/$(TARGET)"

uninstall:
	rm -f $(BINDIR)/$(TARGET)
	@echo "omapass removido de $(BINDIR)/$(TARGET)"

clean:
	rm -rf $(BUILD_DIR) $(TEST_BUILD_DIR)

distclean: clean
