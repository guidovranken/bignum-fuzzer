#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <bndiff/config.h>
#include <bndiff/operation.h>
#include <bndiff/module.h>

#include "runner.h"
#include "multi.h"

bool Runner::run(void) {
    uint8_t numbers[NUM_BIGNUMS][BNSTR_LEN];
    bool ret = false;
    bool compare = true;
    size_t loops = 0;

    if ( input->extract((uint8_t*)numbers, sizeof(numbers)) == false ) {
        return false;
    }

    if ( multi->initialize() == false ) {
        goto end;
    }

    for (size_t i = 0; i < NUM_BIGNUMS; i++) {
        if ( multi->bignum_from_bin(numbers[i], BNSTR_LEN, i) == false ) {
            goto end;
        }
    }

    operation_t operation;
    while ( input->extract(&operation, sizeof(operation)) == true ) {
        loops++;
        uint8_t opt;
        if ( input->extract(&opt, sizeof(opt)) != true ) {
            break;
        }

        if ( multi->exec_operation(operation, opt) == false ) {
            compare = false;
            break;
        }

        if ( multi->compare() == false ) {
            abort();
        }


        /* Swap two arbitrary bignums */
        uint8_t swap_a, swap_b;
        if ( input->extract(&swap_a, sizeof(swap_a)) != true ) {
            break;
        }
        if ( input->extract(&swap_b, sizeof(swap_b)) != true ) {
            break;
        }

        swap_a %= NUM_BIGNUMS;
        swap_b %= NUM_BIGNUMS;

        multi->swap_bignum(swap_a, swap_b);

        if ( loops == 2 ) {
            break;
        }
    }

    if ( compare == true ) {
        if ( multi->compare() == false ) {
            abort();
        }
    }

end:
    multi->shutdown();
    return ret;
}
