#include <stdint.h>
#include <stdlib.h>
#include <bnfuzz/module_cxx.h>
#include "runner.h"

extern module_t mod_openssl;
extern module_t mod_go;
extern module_t mod_cpp_boost;
extern module_t mod_rust;

bool g_logging, g_no_negative, g_no_compare;

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    int i;
    char** _argv = *argv;

    g_logging = false;
    g_no_negative = false;
    g_no_compare = false;

    for (i = 0; i < *argc; i++) {
        if ( !strcmp(_argv[i], "--logging") ) {
            g_logging = true;
        }
        else if ( !strcmp(_argv[i], "--no_negative") ) {
            g_no_negative = true;
        }
        else if ( !strcmp(_argv[i], "--no_compare") ) {
            g_no_compare = true;
        }
        else {
            if ( _argv[i][0] == '-' && _argv[i][1] == '-' ) {
                printf("Invalid option: %s\n", _argv[i]);
                exit(0);
            }
        }
    }

    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    module_container_t modules;

    modules.push_back(&mod_openssl);
    modules.push_back(&mod_rust);
    modules.push_back(&mod_go);
    modules.push_back(&mod_cpp_boost);

    int ret;
    Runner* runner = new Runner(data, size, modules);

    if ( g_logging == true ) {
        runner->SetLogging(true);
    }
    if ( g_no_negative == true ) {
        runner->SetNegative(false);
    }

    ret = runner->run() == true ? 1 : 0;
    delete runner;
    return ret;
}
