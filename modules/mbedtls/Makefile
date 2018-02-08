CFLAGS+=-I../../include
all: module.a
module.a: module.o
	test $(MBEDTLS_LIBMBEDCRYPTO_A_PATH)
	bash ../link.sh module.a $(MBEDTLS_LIBMBEDCRYPTO_A_PATH)
	ranlib module.a
module.o: module.c
	test $(MBEDTLS_INCLUDE_PATH)
	$(CC) $(CFLAGS) -fPIC -c module.c -I $(MBEDTLS_INCLUDE_PATH) -o module.o
clean:
	rm -rf module.o module.a
