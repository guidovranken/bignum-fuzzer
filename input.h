#ifndef BNDIFF_INPUT_H
#define BNDIFF_INPUT_H
#include <bndiff/operation.h>
#include <bndiff/config.h>
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
