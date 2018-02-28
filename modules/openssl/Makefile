all: module.a

CFLAGS+=-I../../include
module.a: module.o operations.o sanity.o tests.o
	test $(OPENSSL_LIBCRYPTO_A_PATH)
	bash ../link.sh module.a $(OPENSSL_LIBCRYPTO_A_PATH) operations.o sanity.o tests.o
	ranlib module.a
module.o: module.c
	test $(OPENSSL_INCLUDE_PATH)
	$(CC) $(CFLAGS) -I $(OPENSSL_INCLUDE_PATH) -fPIC -c module.c -o module.o
operations.o : operations.c
	test $(OPENSSL_INCLUDE_PATH)
	$(CC) $(CFLAGS) -I $(OPENSSL_INCLUDE_PATH) -fPIC -c operations.c -o operations.o
sanity.o : sanity.c
	test $(OPENSSL_INCLUDE_PATH)
	$(CC) $(CFLAGS) -I $(OPENSSL_INCLUDE_PATH) -fPIC -c sanity.c -o sanity.o
tests.o : tests.c
	test $(OPENSSL_INCLUDE_PATH)
	$(CC) $(CFLAGS) -I $(OPENSSL_INCLUDE_PATH) -fPIC -c tests.c -o tests.o
clean:
	rm -rf module.o operations.o sanity.o tests.o module.a
