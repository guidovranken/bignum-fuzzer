#ifndef BNFUZZ_INPUT_H
#define BNFUZZ_INPUT_H
#include <bnfuzz/operation.h>
#include <bnfuzz/config.h>
#include <stdint.h>
#include <stdlib.h>
class Input {
    private:
        const uint8_t *orig_data, *data;
        size_t orig_datasize, datasize;
    public:
        Input(const uint8_t* _data, size_t _size) {
            orig_data = _data;
            orig_datasize = _size;
            rewind();
        }
        bool extract(uint8_t* dest, size_t size);
        void rewind(void);
};
#endif
