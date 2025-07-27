CC      = gcc
CFLAGS  = -std=c99 -Wall -Wextra -Werror
TARGET  = wish

all: $(TARGET)

$(TARGET): wish.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	-rm -f $(TARGET)