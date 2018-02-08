all: module.a

CFLAGS+=-I../../include
module.a: module.o
	test $(OPENSSL_LIBCRYPTO_A_PATH)
	bash ../link.sh module.a $(OPENSSL_LIBCRYPTO_A_PATH)
	ranlib module.a
module.o: module.c
	test $(OPENSSL_INCLUDE_PATH)
	$(CC) $(CFLAGS) -I $(OPENSSL_INCLUDE_PATH) -fPIC -c module.c -o module.o
clean:
	rm -rf module.o module.a
