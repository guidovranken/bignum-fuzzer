CFLAGS+=-I../../include
all: module.a
module.a: module.o
	bash ../link.sh module.a additional_module.a
	ranlib module.a
module.o: module.c
	$(CC) $(CFLAGS) -fPIC -c module.c -o module.o
clean:
	rm -rf module.o module.a
