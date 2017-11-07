CXX=clang++
CFLAGS=-Wall -O3 -g -I../../include -std=c++11 -g -Wall -I include -fsanitize-coverage=trace-pc-guard,indirect-calls,trace-cmp,trace-gep,trace-div,pc-table,edge -fsanitize=address

all: module.a
module.a: module.o
	ar rcs module.a module.o
	ranlib module.a
module.o: module.cpp
	$(CXX) $(CFLAGS) -fPIC -c module.cpp -o module.o
clean:
	rm -rf module.o module.a
