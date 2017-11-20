#include <stdint.h>
#include <stdlib.h>
#include <bndiff/module_cxx.h>
#include "runner.h"

extern module_t mod_openssl;
extern module_t mod_go;
extern module_t mod_cpp_boost;
extern module_t mod_rust;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    module_container_t modules;

    modules.push_back(&mod_openssl);
    modules.push_back(&mod_rust);
    modules.push_back(&mod_go);
    modules.push_back(&mod_cpp_boost);

    int ret;
    Runner* runner = new Runner(data, size, modules);
    ret = runner->run() == true ? 1 : 0;
    delete runner;
    return ret;
}
