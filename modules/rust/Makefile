CC=clang
CFLAGS=-Wall -O3 -g3 -I../../include -fsanitize-coverage=trace-pc-guard,indirect-calls,trace-cmp,trace-gep,trace-div,pc-table,edge
all: module.a
rust/target/release:
	cd rust; cargo rustc --release -- -Cpasses=sancov -Cllvm-args="-sanitizer-coverage-level=3  -sanitizer-coverage-trace-pc-guard" --crate-type=staticlib  --target x86_64-unknown-linux-gnu
module.a: module.o
	bash ../link.sh module.a rust/target/release/deps/librust_bignum_fuzzer*.a
	ranlib module.a
module.o: module.c
	$(CC) $(CFLAGS) -fPIC -c module.c -o module.o
clean:
	rm -rf module.o module.a
