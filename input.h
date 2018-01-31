#ifndef BNFUZZ_INPUT_H
#define BNFUZZ_INPUT_H
#include <bnfuzz/operation.h>
#include <bnfuzz/config.h>
#include <stdint.h>
#include <stdlib.h>
class Input {
    private:
        const uint8_t* data;
        size_t datasize;
    public:
        Input(const uint8_t* _data, size_t _size) {
            data = _data;
            datasize = _size;
        }
        bool extract(uint8_t* dest, size_t size);
};
#endif
