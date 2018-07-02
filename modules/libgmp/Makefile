CFLAGS+=-I../../include
all: module.a
module.a: module.o
	test $(LIBGMP_A_PATH)
	bash ../link.sh module.a $(LIBGMP_A_PATH)
	ranlib module.a
module.o: module.c
	test $(LIBGMP_INCLUDE_PATH)
	$(CC) $(CFLAGS) -fPIC -c module.c -I $(LIBGMP_INCLUDE_PATH) -o module.o
clean:
	rm -rf module.o module.a
