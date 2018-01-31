#include <stdio.h>
#include "input.h"
#include "multi.h"
class Runner {
    public:
        Runner(const uint8_t* data, size_t size, module_container_t loadmodules) {
            input = new Input(data, size);
            multi = new Multi(loadmodules);
        }
        ~Runner(void) {
            delete input;
            delete multi;
        }
        bool run(void);
        void SetLogging(const bool setlogging);
        void SetNegative(const bool setnegative);
    private:
        Input* input;
        Multi* multi;
};
