CC = gcc
CFLAGS = -O2 -Wall
LDFLAGS = -lpthread
TARGET = reaper
SRC = src/reaper.c
PREFIX ?= /usr/local

all: $(TARGET)

$(TARGET): $(SRC)
$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

install: $(TARGET)
install -m 755 $(TARGET) $(PREFIX)/bin/

uninstall:
rm -f $(PREFIX)/bin/$(TARGET)

clean:
rm -f $(TARGET)

.PHONY: all install uninstall clean
