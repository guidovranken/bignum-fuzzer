CFLAGS+=-I../../include
all: module.a
module.a: module.o
	test $(LIBMPDEC_A_PATH)
	bash ../link.sh module.a $(LIBMPDEC_A_PATH)
	ranlib module.a
module.o: module.c
	test $(LIBMPDEC_INCLUDE_PATH)
	$(CC) $(CFLAGS) -fPIC -c module.c -I $(LIBMPDEC_INCLUDE_PATH) -o module.o
clean:
	rm -rf module.o module.a
