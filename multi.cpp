#include "multi.h"
#include <stdio.h>
#include <string.h>

bool Multi::initialize(void) {
    size_t i = 0;
    for ( auto curmod : modules ) {
        if ( curmod->mod->initialize() != 0 ) {
            /* TODO consider marking module as inactive rather than failing altogether */
            return false;
        }
        curmod->clearBn();
        module_active[i] = true;
        i++;
    }
    return true;
}

bool Multi::bignum_from_bin(const uint8_t* data, size_t size, size_t bn_idx) {
    size_t mod_idx = 0;

    /* Convert binary to decimal string */
    char* string = (char*)malloc(size+1);
    for (size_t i = 0; i < size; i++) {
        if ( negative == true && i == 0 ) {
            /* The first character may be [0123456789-]
             * - is to denote a negative value
             */
            string[i] = data[i] % 11;
            if ( string[i] == 10 ) {
                string[i] = '-';
            } else {
                string[i] += '0';
            }
        } else {
            /* All other characters may be [0123456789] */
            string[i] = data[i] % 10 + '0';
        }
    }
    string[size] = 0;

    for ( auto curmod : modules ) {
        if ( curmod->mod->bignum_from_string(string, curmod->getBnIdxPtr(bn_idx)) != 0 ) {
            /* TODO consider marking module as inactive rather than failing altogether */
            free(string);
            return false;
        }
        if ( logging ) {
            printf("%s: %s #%zu: %s\n", __FUNCTION__, curmod->mod->name, bn_idx, string);
        }
        mod_idx++;
    }
    if ( logging ) {
        printf("\n");
    }
    free(string);

    return true;
}

void Multi::bignum_string_reset(void) {
}

void Multi::bignum_string_free(void) {
}

bool Multi::exec_operation(operation_t operation, uint8_t opt) {
    if ( logging ) {
        printf("%s: operation %zu, opt %zu\n", __FUNCTION__, (size_t)operation, (size_t)opt);
    }
    size_t module_idx = 0, num_failed = 0;
    for ( auto curmod : modules ) {
        if ( curmod->mod->operation(curmod->bn, operation, opt) != 0 ) {
            num_failed++;
            module_active[module_idx] = false;
        }
        module_idx++;
    }

    return num_failed != modules.size();
}

void Multi::destroy_bignum(void) {
    for ( auto curmod : modules ) {
        for (size_t bn_idx = 0; bn_idx < NUM_BIGNUMS; bn_idx++) {
            curmod->mod->destroy_bignum(curmod->getBnIdx(bn_idx));
            *(curmod->getBnIdxPtr(bn_idx)) = NULL; /* To avoid double-frees */
        }
    }
}

void Multi::log_state(std::vector< std::pair<size_t, std::vector<char*>> > strings) {
    /* Represents index in 'strings' parameter */
    size_t i = 0;

    for ( const auto& curstrings : strings ) {
        /* curstrings.first is the module index */
        ModuleCtx* curmod = modules[curstrings.first];

        for (size_t bn_idx = 0; bn_idx < NUM_BIGNUMS; bn_idx++) {

            printf("%s: %s #%zu: %s", __FUNCTION__, curmod->mod->name, bn_idx, curstrings.second[bn_idx]);

            /* Compare with previous module */
            if ( i > 0 && decimal_strcmp(strings[i].second[bn_idx], strings[i-1].second[bn_idx]) ) {
                printf(" (does not match)");
            }

            printf("\n");
        }
        printf("\n");
        i++;
    }

    printf("\n");
}

bool Multi::compare(void) {
    std::vector< std::pair<size_t, std::vector<char*>> > strings;
    size_t module_idx = 0;

    /* Step 1: convert bignums to decimal string representation */
    for ( auto curmod : modules ) {
        /* Ignore modules that have been marked inactive during this iteration */
        if ( module_active[module_idx] == false ) {
            module_idx++;
            continue;
        }

        std::vector<char*> curstrings;
        bool do_continue = false;
        for (size_t bn_idx = 0; bn_idx < NUM_BIGNUMS; bn_idx++) {
            char* res;
            /* If bignum to string conversion fails, mark this module as inactive,
             * and refrain from processing the remainder of bignums of this module */
            if ( curmod->mod->string_from_bignum(curmod->getBnIdx(bn_idx), &res) != 0 ) {
                do_continue = true;
                module_active[module_idx] = false;
                break;
            }
            curstrings.push_back(res);
        }

        /* If bignum to string conversion failed, do not compare its bignums */
        if ( do_continue == true ) {
            module_idx++;
            continue;
        }

        strings.push_back(std::pair<size_t, std::vector<char*>>(module_idx, curstrings));
        module_idx++;
    }

    /* Step 2: compare strings */
    bool ret = true;

    for (size_t i = 1; i < strings.size(); i++) {
        auto prevstrings = strings[i-1].second;
        auto curstrings = strings[i].second;

        for (size_t bn_idx = 0; bn_idx < NUM_BIGNUMS; bn_idx++) {
            if ( decimal_strcmp(curstrings[bn_idx], prevstrings[bn_idx]) ) {
                ret = false;
                break;
            }
        }

        if ( ret == false ) {
            break;
        }
    }

    if ( logging == true ) {
        log_state(strings);
    }

    for ( auto curstrings : strings ) {
        for ( auto string : curstrings.second ) {
            free(string);
        }
    }

    return ret;
}

int Multi::decimal_strcmp(const char *s1, const char *s2)
{
    int ret;

    /* Don't differentiate between negative and positive 0 */
    if ( strcmp(s1, "-0") == 0 && strcmp(s2, "0") == 0 ) {
        return 0;
    }
    if ( strcmp(s2, "-0") == 0 && strcmp(s1, "0") == 0 ) {
        return 0;
    }

    if ( *s1 == '-' || *s2 == '-' ) {
        if ( *s1 != *s2 ) {
            /* One string starts with the minus sign and the other does not */
            return -1;
        }
        s1++;
        s2++;
    }

    /* Skip leading zeroes */
    while ( *s1 == '0' && *(s1+1) != 0x00 ) s1++;
    while ( *s2 == '0' && *(s2+1) != 0x00 ) s2++;

    ret = strcmp(s1, s2);

    return ret;
}

void Multi::swap_bignum(size_t a, size_t b) {
    for ( auto curmod : modules ) {
        void* tmp, **A = curmod->getBnIdxPtr(a), **B = curmod->getBnIdxPtr(b);
        tmp = *A;
        *A = *B;
        *B = tmp;
    }
}

void Multi::shutdown(void) {
    for ( auto curmod : modules ) {
        curmod->mod->shutdown();
    }
    destroy_bignum();
}
void Multi::SetLogging(const bool setlogging) {
    logging = setlogging;
}
void Multi::SetNegative(const bool setnegative) {
    negative = setnegative;
}
