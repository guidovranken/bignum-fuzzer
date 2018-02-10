#include "input.h"
#include <string.h>

bool Input::extract(uint8_t* dest, size_t size) {
    if ( datasize < size ) {
        return false;
    }

    memcpy(dest, data, size);
    data += size;
    datasize -= size;

    return true;
}

void Input::rewind(void) {
    data = orig_data;
    datasize = orig_datasize;
}
