# NullSec RKHunt Makefile

CC = gcc
CFLAGS = -Wall -Wextra -O2 -D_GNU_SOURCE
LDFLAGS = 

TARGET = rkhunt
SRC = src/rkhunt.c

PREFIX ?= /usr/local
BINDIR = $(PREFIX)/bin

.PHONY: all clean install uninstall

all: $(TARGET)

$(TARGET): $(SRC)
$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
rm -f $(TARGET)

install: $(TARGET)
install -Dm755 $(TARGET) $(DESTDIR)$(BINDIR)/$(TARGET)

uninstall:
rm -f $(DESTDIR)$(BINDIR)/$(TARGET)
