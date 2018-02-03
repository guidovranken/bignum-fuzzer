#include <stdint.h>
#include <stdlib.h>
#include <bnfuzz/module_cxx.h>
#include "runner.h"

extern module_t mod_openssl;
extern module_t mod_go;
extern module_t mod_cpp_boost;
extern module_t mod_rust;

bool g_logging, g_no_negative, g_no_compare;

size_t num_len;
size_t operation;

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    int i;
    char** _argv = *argv;

    g_logging = false;
    g_no_negative = false;
    g_no_compare = false;
    num_len = 0;
    operation = 0;

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
        else if ( !strncmp(_argv[i], "--num_len=", 10) ) {
            long l;
            l = strtol(_argv[i]+10, NULL, 10);
            if ( l < 1 ) {
                printf("Invalid --num_len argument\n");
                exit(0);
            }
            num_len = (size_t)l;

        }
        else if ( !strncmp(_argv[i], "--operation=", 12) ) {
            long l;
            l = strtol(_argv[i]+12, NULL, 10);
            if ( l < 1 ) {
                printf("Invalid --operation argument\n");
                exit(0);
            }
            operation = (size_t)l;

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
    if ( g_no_compare == true ) {
        runner->SetCompare(false);
    }
    if ( num_len != 0 ) {
        runner->SetNumberLength(num_len);
    }
    if ( operation != 0 ) {
        runner->SetOperation(operation);
    }

    ret = runner->run() == true ? 1 : 0;
    delete runner;
    return ret;
}
