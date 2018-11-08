export CC="clang"
export CXX="clang++"
export CFLAGS="-fsanitize-coverage=trace-pc-guard -g -O3"
export CXXFLAGS="-fsanitize-coverage=trace-pc-guard -g -O3"

git clone git@github.com:guidovranken/bignum-fuzzer.git
git clone git@github.com:guidovranken/libfuzzer-gv.git

cd libfuzzer-gv/
make -j6
export LIBFUZZER_LINK=`realpath libFuzzer.a`
cd ..

cd bignum-fuzzer
git checkout uint256
./config-modules.sh holiman_uint256 cpp_boost_uint256 trezor_crypto

# build holiman_uint256 module
cd modules/holiman_uint256
make
cd ../..

# build cpp_boost_uint256 module
cd modules/cpp_boost_uint256
make
cd ../..

# build trezor_crypto module
cd modules/trezor_crypto
make
cd ../..

make
./fuzzer -custom_guided=1 -use_value_profile=1 --num_len=80 --all_operations --no_negative --num_loops=1  -max_len=400 -timeout=10 corpus_uint256/

