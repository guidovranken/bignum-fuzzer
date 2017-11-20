CXX=clang++
CXXFLAGS=-std=c++11 -g -Wall -I include -fsanitize-coverage=trace-pc-guard,indirect-calls,trace-cmp,trace-gep,trace-div,pc-table,edge -fsanitize=address
fuzzer: fuzzer.cpp runner.cpp runner.h multi.cpp multi.h input.cpp input.h
	$(CXX) $(CXXFLAGS) -c fuzzer.cpp -o fuzzer.o
	$(CXX) $(CXXFLAGS) -c multi.cpp -o multi.o
	$(CXX) $(CXXFLAGS) -c runner.cpp -o runner.o
	$(CXX) $(CXXFLAGS) -c input.cpp -o input.o
	$(CXX) $(CXXFLAGS) fuzzer.o multi.o runner.o input.o libFuzzer.a modules/openssl/module.a modules/go/module.a modules/cpp_boost/module.a modules/rust/module.a -lpthread -o bnfuzzer
