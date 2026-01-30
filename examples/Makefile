MAKE		= make
CC			= gcc
INCLUDES	= -I../include
LIBS		= ../build/libflock.a -lcrypto -lssl -largon2

LOCKER		= locker
LOCKER_SRC	= locker.c

all: $(LOCKER)


$(LOCKER): $(LIBS) $(LOCKER_SRC)
	$(CC) -o $@ $(LOCKER_SRC) $(INCLUDES) $(LIBS)


$(LIBS):
	$(MAKE) -C ..

clean:
	rm -rf $(LOCKER)
	$(MAKE) -C .. clean
