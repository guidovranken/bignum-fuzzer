#include <stdio.h>
#include "input.h"
#include "multi.h"
class Runner {
    public:
        Runner(module_container_t loadmodules) {
            multi = new Multi(loadmodules);
            compare = true;
            swapswapop = false;
            num_len = 500;
            operation = 0;
            num_loops = 2;
        }
        ~Runner(void) {
            delete multi;
        }
        bool run(Input& input);
        void SetLogging(const bool setlogging);
        void SetNegative(const bool setnegative);
        void SetCompare(const bool setcompare);
        void SetSwapSwapOp(const bool setswapswapop);
        void SetNumberLength(const size_t _num_len);
        void SetOperation(const size_t operation);
        void SetNumLoops(const size_t _num_loops);
    private:
        bool compare, swapswapop;
        size_t num_len;
        size_t operation;
        size_t num_loops;
        Multi* multi;
};
