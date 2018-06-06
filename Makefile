

CC = gcc

CFLAGSFUSE = -D_FILE_OFFSET_BITS=64 -I/usr/include/fuse
LLIBSFUSE = -pthread -lfuse
LLIBSOPENSSL = -lcrypto

CFLAGS = -c -g -Wall
LFLAGS = -g -Wall -Wextra

FUSE_EXAMPLES = fusehello fusexmp pa4-encfs
XATTR_EXAMPLES = xattr-util
OPENSSL_EXAMPLES = aes-crypt-util

.PHONY: all fuse-examples xattr-examples openssl-examples clean

all: fuse-examples xattr-examples openssl-examples

fuse-examples: $(FUSE_EXAMPLES)
xattr-examples: $(XATTR_EXAMPLES)
openssl-examples: $(OPENSSL_EXAMPLES)

fusehello: fusehello.o
	$(CC) $(LFLAGS) $^ -o $@ $(LLIBSFUSE)

fusexmp: fusexmp.o
	$(CC) $(LFLAGS) $^ -o $@ $(LLIBSFUSE)

pa4-encfs: pa4-encfs.o aes-crypt.o
	$(CC) $(LFLAGS) $^ -o $@ $(LLIBSFUSE) $(LLIBSOPENSSL)

xattr-util: xattr-util.o
	$(CC) $(LFLAGS) $^ -o $@

aes-crypt-util: aes-crypt-util.o aes-crypt.o
	$(CC) $(LFLAGS) $^ -o $@ $(LLIBSOPENSSL)

fusehello.o: fusehello.c
	$(CC) $(CFLAGS) $(CFLAGSFUSE) -o $@ $<

fusexmp.o: fusexmp.c
	$(CC) $(CFLAGS) $(CFLAGSFUSE) -o $@ $<

pa4-encfs.o: pa4-encfs.c
	$(CC) $(CFLAGS) $(CFLAGSFUSE) $<

xattr-util.o: xattr-util.c
	$(CC) $(CFLAGS) -o $@ $<

aes-crypt-util.o: aes-crypt-util.c aes-crypt.h
	$(CC) $(CFLAGS) -o $@ $<

aes-crypt.o: aes-crypt.c aes-crypt.h
	$(CC) $(CFLAGS) -o $@ $<

unmount:
	fusermount -u mir

debug: clean pa4-encfs
	./pa4-encfs -d mnt/ mir/ -e password

mount: clean pa4-encfs
	./pa4-encfs mnt/ mir/ -e password

clean:
	rm -f $(FUSE_EXAMPLES)
	rm -f $(XATTR_EXAMPLES)
	rm -f $(OPENSSL_EXAMPLES)
	rm -f pa4-encfs
	rm -f *.o
	rm -f *~
	rm -f handout/*~
	rm -f handout/*.log
	rm -f handout/*.aux
	rm -f handout/*.out
