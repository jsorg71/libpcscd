PCSCLITE_CFLAGS=$(shell pkg-config --cflags libpcsclite)
PCSCLITE_LIBS=$(shell pkg-config --libs libpcsclite)

OBJS=test_reconnect.o

CFLAGS=-fPIC -g -O2 -Wall $(PCSCLITE_CFLAGS)

LDFLAGS=$(PCSCLITE_LIBS)

LIBS=

test_reconnect: $(OBJS) $(LIBS)
	$(CC) -o test_reconnect $(OBJS) $(LDFLAGS) $(LIBS)

clean:
	rm -f test_reconnect $(OBJS)
