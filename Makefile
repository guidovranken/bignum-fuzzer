CXXFLAGS+=-std=c++11 -I include
fuzzer: fuzzer.cpp runner.cpp runner.h multi.cpp multi.h input.cpp input.h
	$(CXX) $(CXXFLAGS) -c fuzzer.cpp -o fuzzer.o
	$(CXX) $(CXXFLAGS) -c multi.cpp -o multi.o
	$(CXX) $(CXXFLAGS) -c runner.cpp -o runner.o
	$(CXX) $(CXXFLAGS) -c input.cpp -o input.o
	sh link.sh
clean:
	rm -rf declare_modules.h push_modules.h *.o fuzzer
