CXXFLAGS+=-I../../include -std=c++11

all: module.a
module.a: module.o bignum.o memzero.o
	ar -rcs module.a bignum.o memzero.o module.o
	ranlib module.a
module.o: module.cpp
	$(CXX) $(CXXFLAGS) -fPIC -c module.cpp -o module.o
bignum.o : src/bignum.c
	$(CC) $(CFLAGS) -fPIC -c src/bignum.c 
memzero.o : src/memzero.c
	$(CC) $(CFLAGS) -fPIC -c src/memzero.c 
clean:
	rm -rf module.o module.a bignum.o memzero.o
