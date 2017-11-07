#ifndef BNDIFF_MULTI_H
#define BNDIFF_MULTI_H
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <bndiff/module_cxx.h>

class ModuleCtx {
    public:
        ModuleCtx(module_t * _mod) {
            mod = _mod;
            bn = new bignum_cluster_t();
        }
        ~ModuleCtx() {
            delete bn;
        }
        void* getBnPtr() {
            return bn->BN;
        }
        void* getBnIdx(size_t idx) {
            return bn->BN[idx];
        }
        void** getBnIdxPtr(size_t idx) {
            return &(bn->BN[idx]);
        }
        void clearBn() {
            memset(bn, 0, sizeof(*bn));
        }
        module_t* mod;
        bignum_cluster_t* bn;
};

class Multi {
    public:
        Multi(module_container_t loadmodules) {
            for ( auto curmod : loadmodules ) {
                modules.push_back( new ModuleCtx(curmod) );

            }
            //logging = true;
        }
        ~Multi() {
            destroy_bignum();
            for ( auto curmod : modules ) {
                delete curmod;
            }
        }
        bool initialize(void);
        bool bignum_from_bin(const uint8_t* data, size_t size, size_t bn_index);
        void bignum_string_reset(void);
        void bignum_string_free(void);
        bool exec_operation(operation_t operation, uint8_t op);
        bool compare(void);
        void destroy_bignum(void);
        void shutdown(void);
        void swap_bignum(size_t a, size_t b);
    private:
        bool logging;
        size_t get_num_modules(void);
        std::vector<ModuleCtx*> modules;
        int decimal_strcmp(const char *s1, const char *s2);
        void log_state(std::vector<std::vector<char*>> strings);
};
#endif
