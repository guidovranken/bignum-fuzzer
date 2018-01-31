CC=clang
CFLAGS=-Wall -O3 -g3 -I../../include -fsanitize-coverage=trace-pc-guard,indirect-calls,trace-cmp,trace-gep,trace-div,edge
all: module.a
librust_bignum_fuzzer.a:
	cd rust; cargo rustc --release -- -Cpasses=sancov -Cllvm-args="-sanitizer-coverage-level=3 -sanitizer-coverage-trace-pc-guard -sanitizer-coverage-trace-compares=1 -sanitizer-coverage-trace-geps=1 -sanitizer-coverage-trace-divs=1" --crate-type=staticlib  --target x86_64-unknown-linux-gnu
	cp rust/target/release/deps/librust_bignum_fuzzer*.a librust_bignum_fuzzer.a
module.a: module.o librust_bignum_fuzzer.a
	bash ../link.sh module.a librust_bignum_fuzzer.a
	ranlib module.a
module.o: module.c
	$(CC) $(CFLAGS) -fPIC -c module.c -o module.o
clean:
	rm -rf module.o module.a librust_bignum_fuzzer.a rust/target/release
