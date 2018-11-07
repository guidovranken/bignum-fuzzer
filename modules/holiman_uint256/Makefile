CFLAGS+=-I../../include
all: module.a 

go:
	wget https://dl.google.com/go/go1.11.1.linux-amd64.tar.gz
	tar zxvf go1.11.1.linux-amd64.tar.gz
go/packages/src/github.com/holiman/uint256: go
	GOPATH=`realpath go/packages` GOROOT=`realpath go` go/bin/go get -u github.com/holiman/uint256
go/packages/src/github.com/guidovranken/libfuzzer-go: go
	mkdir -p go/packages/src/github.com/guidovranken
	cd go/packages/src/github.com/guidovranken && git clone https://github.com/guidovranken/libfuzzer-go.git
go-fuzz-build : go/packages/src/github.com/guidovranken/libfuzzer-go
	GOPATH=`realpath go/packages` GOROOT=`realpath go` go/bin/go build github.com/guidovranken/libfuzzer-go/go-fuzz-build
holiman_uint256.a : go-fuzz-build go/packages/src/github.com/holiman/uint256 holiman_uint256_fuzzer_mainsrc.go
	PATH=`realpath go/bin`:$(PATH) GOPATH=`realpath go/packages` GOROOT=`realpath go` ./go-fuzz-build -mainsrc holiman_uint256_fuzzer_mainsrc.go -o holiman_uint256.a github.com/holiman/uint256
module.o : module.c holiman_uint256.a
	$(CC) $(CFLAGS) -c module.c
module.a: module.o holiman_uint256.a
	bash ../link.sh module.a holiman_uint256.a
	ranlib module.a

clean:
	rm -rf *.tar.gz go/ go-fuzz-build holiman_uint256.a holiman_uint256.h module.o module.a
