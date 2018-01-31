#include <stdio.h>
#include "input.h"
#include "multi.h"
class Runner {
    public:
        Runner(const uint8_t* data, size_t size, module_container_t loadmodules) {
            input = new Input(data, size);
            multi = new Multi(loadmodules);
            compare = true;
        }
        ~Runner(void) {
            delete input;
            delete multi;
        }
        bool run(void);
        void SetLogging(const bool setlogging);
        void SetNegative(const bool setnegative);
        void SetCompare(const bool setcompare);
    private:
        bool compare;
        Input* input;
        Multi* multi;
};
