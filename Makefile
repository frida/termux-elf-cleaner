CXXFLAGS += -std=c++11 -Wall -Wextra -pedantic
PREFIX ?= /usr/local

frida-elf-cleaner: frida-elf-cleaner.cpp

clean:
	rm -f frida-elf-cleaner

install: frida-elf-cleaner
	mkdir -p $(DESTDIR)$(PREFIX)/bin
	install frida-elf-cleaner $(DESTDIR)$(PREFIX)/bin/frida-elf-cleaner

uninstall:
	rm -f $(PREFIX)/bin/frida-elf-cleaner

.PHONY: clean install uninstall
