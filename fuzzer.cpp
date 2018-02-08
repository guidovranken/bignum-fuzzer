#include <stdint.h>
#include <stdlib.h>
#include <bnfuzz/module_cxx.h>
#include "runner.h"

#include "declare_modules.h"

bool g_logging, g_no_negative, g_no_compare, g_all_operations;

size_t num_len;
size_t operation;

static void print_help(void)
{
    printf("\n");
    printf("Bignum fuzzer by Guido Vranken -- https://github.com/guidovranken/bignum-fuzzer\n");
    printf("\n");
    printf("Valid command-line parameters:\n");
    printf("\n");
    printf("\t--logging : print input bignums, operation # and output bignums\n");
    printf("\t--no_negative : interpret all input bignums as positive integers \n");
    printf("\t--no_compare : disable differential fuzzing; don't compare output bignums across modules\n");
    printf("\t--num_len=<n>: input bignum size in number of decimal digits\n");
    printf("\t--operation=<n> : disregard operation encoded in input; run each iteration with this operation\n");
    printf("\t--all_operations : disregard operation encoded in input; run each iteration with all operations\n");
    printf("\n");
    exit(0);
}

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    int i;
    char** _argv = *argv;

    g_logging = false;
    g_no_negative = false;
    g_no_compare = false;
    g_all_operations = false;
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
                print_help();
            }
            num_len = (size_t)l;

        }
        else if ( !strncmp(_argv[i], "--operation=", 12) ) {
            long l;
            l = strtol(_argv[i]+12, NULL, 10);
            if ( l < 1 ) {
                printf("Invalid --operation argument\n");
                print_help();
            }
            operation = (size_t)l;

        }
        else if ( !strcmp(_argv[i], "--all_operations") ) {
            g_all_operations = true;
        }
        else if ( !strcmp(_argv[i], "--help") ) {
            print_help();
        }
        else {
            if ( _argv[i][0] == '-' && _argv[i][1] == '-' ) {
                printf("Invalid option: %s\n", _argv[i]);
                print_help();
            }
        }
    }

    if ( g_all_operations == true && operation != 0 ) {
        printf("You cannot specify --operation and --all_operations at the same time\n");
        print_help();
    }

#ifdef BNFUZZ_FLAG_NO_NEGATIVE
    g_no_negative = true;
#endif

#ifdef BNFUZZ_FLAG_NO_COMPARE
    g_no_compare = true;
#endif

#ifdef BNFUZZ_FLAG_NUM_LEN
    num_len = BNFUZZ_FLAG_NUM_LEN;
#endif

#ifdef BNFUZZ_FLAG_OPERATION
    operation = BNFUZZ_FLAG_OPERATION;
#endif

#ifdef BNFUZZ_FLAG_ALL_OPERATIONS
    g_all_operations = true;
#endif

    return 0;
}

static void run_single(const uint8_t *data, size_t size, module_container_t &modules, operation_t _operation)
{
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
    if ( _operation != 0 ) {
        runner->SetOperation(_operation);
    }
    runner->run();

    delete runner;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    module_container_t modules;

    #include "push_modules.h"

    if ( g_all_operations == true ) {
        for (int i = 0; i < BN_FUZZ_OP_LAST; i++) {
            run_single(data, size, modules, i == 0 ? BN_FUZZ_OP_NOP : (operation_t)i);
        }
    } else {
        run_single(data, size, modules, operation);
    }

    return 0;
}
