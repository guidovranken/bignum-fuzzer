CXX=clang++
CXXFLAGS=-std=c++11 -g -Wall -I include -O3
fuzzer: fuzzer.cpp runner.cpp runner.h multi.cpp multi.h input.cpp input.h
	$(CXX) $(CXXFLAGS) -c fuzzer.cpp -o fuzzer.o
	$(CXX) $(CXXFLAGS) -c multi.cpp -o multi.o
	$(CXX) $(CXXFLAGS) -c runner.cpp -o runner.o
	$(CXX) $(CXXFLAGS) -c input.cpp -o input.o
	$(CXX) -fsanitize-coverage=trace-pc-guard,indirect-calls,trace-cmp,trace-gep,trace-div,edge $(CXXFLAGS) fuzzer.o multi.o runner.o input.o libFuzzer.a modules/evm_geth/module.a modules/evm_parity/module.a -lpthread -o fuzzer
clean:
	rm -rf *.o fuzzer
