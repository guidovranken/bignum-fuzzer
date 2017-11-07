CC=clang
CFLAGS=-Wall -O3 -g3 -I../../include
all: module.a
#bash ../link.sh module.a libcrypto.a
module.a: module.o
	bash ../link.sh module.a ./boringssl/boringssl/build/crypto/libcrypto.a
	ranlib module.a
module.o: module.c
	$(CC) $(CFLAGS) -Iboringssl/boringssl/include -fPIC -c module.c -o module.o
clean:
	rm -rf module.o module.a
