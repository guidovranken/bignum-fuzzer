# bignum-fuzzer

# Fuzzer logic

The fuzzer logic is as follows:

For each iteration:

1. Extract several decimal strings from single libFuzzer input using internal logic
2. Call the ```initialize``` function of every loaded module.
    1. If any ```initialize``` call returns failure, then go to step 9
3. Call the ```bignum_from_string``` function of every loaded module for every decimal string extracted in step 1
    1. If any ```bignum_from_string``` call returns failure, then go to step 9
4. Extract an ```operation_t``` struct and an ```uint8_t``` "opt" value from the libFuzzer input using internal logic
    1. If there is insuffcient data left in the libFuzzer input to extract an ```operation_t``` struct and an ```uint8_t``` "opt" value, then go to step 9
5. Call the ```operation``` function of every loaded module
    1. If any ```operation``` call returns failure, then go to step 9
6. Call the ```string_from_bignum``` function of every loaded module for each of their internal bignum representations
    1. If any ```string_from_bignum``` call returns failure, then go to step 9
7. Compare the strings collected in step 6 with one another, and ```abort()``` if a mismatch is found
8. Go to step 4
9. Call the ```shutdown``` function of every loaded module, and proceed to next iteration

# Implementing a module

Each module must implement a ```module_t``` struct, defined in ```include/bndiff/module.h```.

## Components

Currently, this struct contains 6 instruction pointers and 1 string pointer.

### ```int initialize(void)```

Objective:
- If applicable, allocate resources or initialize objects that must be available throughout a single iteration.

Note:
- This function is called once per iteration.

Return value:
- ```0``` for success
- ```-1``` for failure

### ```int bignum_from_string(const char* input, void** output)```

Objective:
- Convert ```input```, which is a null-terminated, base 10 string representation of an integer, to an internal bignum representation.
- Store the pointer to the internal bignum representation to ```*output```;

Notes:
- The (pointer to the) internal bignum representation must persist in memory until ```destroy_bignum``` is called on it.
- ```input``` may be prefixed by the minus symbol ```-``` do denote that the number that follows it is negative.
- This function performs the inverse operation of ```int string_from_bignum(void* bignum, char** output)```.

Return value:
- ```0``` for success
- ```-1``` for failure

### ```int string_from_bignum(void* bignum, char** output)```

Objective:
- Convert the internal bignum representation pointed to by ```bignum``` to a base 10 null-terminated string.
- Store the pointer to this string in ```*output```

Notes:
- This allocation for the string that this function produces MUST be done with ```malloc()```.
- If the bignum at hand represents a negative value, the output string must be prefixed with the minus symbol ```-```. 
- This function performs the inverse operation of ```int bignum_from_string(const char* input, void** output)```.

Return value:
- ```0``` for success
- ```-1``` for failure

### ```void destroy_bignum(void* bignum)```

Objective:
- Free any resources that the internal bignum representation pointer to by ```bignum``` uses.

Return value:
- Does not return a value

### ```int operation(bignum_cluster_t* bignum_cluster, operation_t operation, uint8_t op)```

Objective:
- Perform ```operation``` on the bignums in ```bignum_cluster```.
- The semantics of each operation type are prescribed in the chapter ```Operations``` below.

Notes:
- This function may return failure (see below) if it does not support the requested operation, or otherwise can not or will not comply to the request.
- The ```op``` variable can be used to choose from several internal, semantically equivalent functions. For example:

```c
    switch ( operation ) {
        ...
        ...
        case    BN_FUZZ_OP_ADD:
            if ( (opt & 1) == 0 ) {
                internal_add_function_1(...);
            } else {
                internal_add_function_2(...);
            }
    }
```

Return value:
- ```0``` for success
- ```-1``` for failure

### ```void shutdown(void)```

Objective:
- If applicable, free resources or destroy objects that must were created with ```int initialize(void)```.

Note:
- This function is called once per iteration.

Return value:
- Does not return a value

### ```const char* name```

Objective: A null-terminated string that is a concise, human-readable description of the module.

### Example of a minimal module

```c
#include <bndiff/module.h>
#include <bndiff/operation.h>
#include <bndiff/bignum.h>

static int initialize(void) { /* TODO */ }
static int bignum_from_string(const char* input, void** output) { /* TODO */ }
static int string_from_bignum(void* input, char** output) { /* TODO */ }
static void destroy_bignum(void* bignum) { /* TODO */ }
static int operation(
        bignum_cluster_t* bignum_cluster,
        operation_t operation,
        uint8_t opt) { /* TODO */ }
static void shutdown(void) { /* TODO */ }

module_t mod_example = {
    .initialize = initialize,
    .bignum_from_string = bignum_from_string,
    .string_from_bignum = string_from_bignum,
    .destroy_bignum = destroy_bignum,
    .operation = operation,
    .shutdown = shutdown,
    .name = "Example module"
};
```

# Operations

Currently supported operations, defined in ```include/bndiff/operation.h```.

In the summary below, the symbols A, B, C and D represent the first, second, third and fourth bignum pointers present in a ```bignum_cluster_t```, respectively.

## BN_FUZZ_OP_ADD
- ```A = B + C```
## BN_FUZZ_OP_SUB
- ```A = B - C```
## BN_FUZZ_OP_MUL
- ```A = B * C```
## BN_FUZZ_OP_DIV
- ```A = B / C```
## BN_FUZZ_OP_MOD
- ```A = B MOD C```
## BN_FUZZ_OP_EXP_MOD
- ```A = (B ** C) MOD D```
## BN_FUZZ_OP_LSHIFT
- ```A = B << 1```
## BN_FUZZ_OP_RSHIFT
- ```A = B >> 1```
## BN_FUZZ_OP_GCD
- ```A = GCD(A, B)```
## BN_FUZZ_OP_MOD_ADD
- ```A = (B + C) MOD D```
## BN_FUZZ_OP_EXP
- ```A = B ** C```
## BN_FUZZ_OP_CMP
- ```if B > C then A = 1```
- ```if B < C then A = -1```
- ```if B == C then A = 0```
## BN_FUZZ_OP_SQR
- ```A = B * B```
## BN_FUZZ_OP_NEG
- ```A = 0 - B```
## BN_FUZZ_OP_ABS
- ```A = ABS(B)```
## BN_FUZZ_OP_IS_PRIME
- ```if B is a prime number then A = 1```
- ```if B is not a prime number then A = 0```
## BN_FUZZ_OP_MOD_SUB
- ```A = (B - C) MOD D```
## BN_FUZZ_OP_SWAP
- ```TMP = A```
- ```A = B```
- ```B = TMP```
## BN_FUZZ_OP_MOD_MUL
- ```A = (B * C) MOD D```
## BN_FUZZ_OP_SET_BIT
- ```A |= 1 << B```
## BN_FUZZ_OP_NOP
- This operation is free to do whatever it wants, but it must not alter any bignums
