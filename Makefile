CC = gcc
CFLAGS = -O2 -Wall -Wextra -D_GNU_SOURCE
LDFLAGS = -lpthread

TARGET = rkhunt
SOURCE = src/rkhunt.c

all: $(TARGET)

$(TARGET): $(SOURCE)
$(CC) $(CFLAGS) -o $(TARGET) $(SOURCE) $(LDFLAGS)

clean:
rm -f $(TARGET)

install: $(TARGET)
cp $(TARGET) /usr/local/bin/rkhunt
chmod 755 /usr/local/bin/rkhunt

.PHONY: all clean install
