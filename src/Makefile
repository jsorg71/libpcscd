
OBJS=libpcscd.o

CFLAGS=-fPIC -g -O2 -Wall -I../include

LDFLAGS=

LIBS=

all: libpcscd.so libpcscd.a

libpcscd.so: $(OBJS)
	$(CC) -shared -o libpcscd.so $(OBJS) $(LDFLAGS) $(LIBS)

libpcscd.a: $(OBJS)
	$(AR) -r libpcscd.a $(OBJS)
	ranlib libpcscd.a

clean:
	rm -f libpcscd.so $(OBJS)
