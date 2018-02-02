CC=clang
CFLAGS=-Wall -O3 -g3 -I../../include -fsanitize-coverage=trace-pc-guard,indirect-calls,trace-cmp,trace-gep,trace-div,edge
all: module.a
lib.a: lib.go
	go build -buildmode=c-archive lib.go
module.a: module.o lib.a
	bash ../link.sh module.a lib.a
	ranlib module.a
module.o: module.c lib.a
	$(CC) $(CFLAGS) -fPIC -c module.c -o module.o
clean:
	rm -rf module.o module.a lib.a lib.h
