#include <stdio.h>
#include "input.h"
#include "multi.h"
class Runner {
    public:
        Runner(const uint8_t* data, size_t size, module_container_t loadmodules) {
            input = new Input(data, size);
            multi = new Multi(loadmodules);
            compare = true;
            num_len = 500;
            operation = 0;
        }
        ~Runner(void) {
            delete input;
            delete multi;
        }
        bool run(void);
        void SetLogging(const bool setlogging);
        void SetNegative(const bool setnegative);
        void SetCompare(const bool setcompare);
        void SetNumberLength(const size_t _num_len);
        void SetOperation(const size_t operation);
    private:
        bool compare;
        size_t num_len;
        size_t operation;
        Input* input;
        Multi* multi;
};
