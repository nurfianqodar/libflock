AR				= ar

CC				= gcc
CFLAGS			= -Wall -Wextra -O2 -Iinclude -Isrc
SRCS			= src/flock.c src/key.c src/file.c src/util.c src/version.c
OBJS			= $(SRCS:src/%.c=build/%.o)
LIB				= build/libflock.a

.PHONY: all clean

all: $(LIB)

$(LIB): $(OBJS)
	$(AR) rcs $@ $^

build/%.o: src/%.c
	@mkdir -p build
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf build/



