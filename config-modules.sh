#!/bin/bash

rm -rf declare_modules.h push_modules.h link.sh

echo -n "\$CXX \$CXXFLAGS fuzzer.o multi.o runner.o input.o \$LIBFUZZER_LINK " >>link.sh

for var in "$@"
do
    if [ $var == "openssl" ] || [ $var == "boringssl" ]; then
        echo "extern module_t mod_openssl;" >>declare_modules.h
        echo "modules.push_back(&mod_openssl);" >>push_modules.h
        echo -n "modules/openssl/module.a -ldl " >>link.sh
    elif [ $var = "go" ]; then
        echo "extern module_t mod_go;" >>declare_modules.h
        echo "modules.push_back(&mod_go);" >>push_modules.h
        echo -n "modules/go/module.a " >>link.sh
    elif [ $var = "rust" ]; then
        echo "extern module_t mod_rust;" >>declare_modules.h
        echo "modules.push_back(&mod_rust);" >>push_modules.h
        echo -n "modules/rust/module.a " >>link.sh
    elif [ $var = "cpp_boost" ]; then
        echo "extern module_t mod_cpp_boost;" >>declare_modules.h
        echo "modules.push_back(&mod_cpp_boost);" >>push_modules.h
        echo -n "modules/cpp_boost/module.a " >>link.sh
    elif [ $var = "mbedtls" ]; then
        echo "extern module_t mod_mbedtls;" >>declare_modules.h
        echo "modules.push_back(&mod_mbedtls);" >>push_modules.h
        echo -n "modules/mbedtls/module.a " >>link.sh
    elif [ $var = "libmpdec" ]; then
        echo "extern module_t mod_libmpdec;" >>declare_modules.h
        echo "modules.push_back(&mod_libmpdec);" >>push_modules.h
        echo -n "modules/libmpdec/module.a " >>link.sh
    elif [ $var = "libgmp" ]; then
        echo "extern module_t mod_libgmp;" >>declare_modules.h
        echo "modules.push_back(&mod_libgmp);" >>push_modules.h
        echo -n "modules/libgmp/module.a " >>link.sh
    elif [ $var = "holiman_uint256" ]; then
        echo "extern module_t mod_holiman_uint256;" >>declare_modules.h
        echo "modules.push_back(&mod_holiman_uint256);" >>push_modules.h
        echo -n "modules/holiman_uint256/module.a " >>link.sh
    else
        echo "Unknown module $var"; rm -rf declare_modules.h push_modules.h link.sh; exit
    fi
done

echo "-lpthread -o fuzzer" >>link.sh
chmod +x ./link.sh
