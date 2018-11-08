CXXFLAGS+=-I../../include -std=c++11

all: module.a
module.a: module.o
	ar rcs module.a module.o
	ranlib module.a
module.o: module.cpp
	$(CXX) $(CXXFLAGS) -fPIC -c module.cpp -o module.o
clean:
	rm -rf module.o module.a
