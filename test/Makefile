
PCSCLITE_CFLAGS=$(shell pkg-config --cflags libpcsclite)
PCSCLITE_LIBS=$(shell pkg-config --libs libpcsclite)

OBJS=call_test.o

CFLAGS=-g -O2 -Wall -I../include $(PCSCLITE_CFLAGS)

LDFLAGS=$(PCSCLITE_LIBS) -lpthread

LIBS=../src/libpcscd.a

call_test: $(OBJS) $(LIBS)
	$(CC) -o call_test $(OBJS) $(LDFLAGS) $(LIBS)

clean:
	rm -f call_test $(OBJS)
