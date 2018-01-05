CC=clang
CFLAGS=-Wall -O3 -g -I../../include -g -Wall -fsanitize-coverage=trace-pc-guard,indirect-calls,trace-cmp,trace-gep,trace-div,pc-table,edge
all: module.a
module.a: module.o
	bash ../link.sh module.a mbedtls-2.6.1/library/libmbedcrypto.a
	ranlib module.a
module.o: module.c
	$(CC) $(CFLAGS) -fPIC -c module.c -I mbedtls-2.6.1/include -o module.o
clean:
	rm -rf module.o module.a
