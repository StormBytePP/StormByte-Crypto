add_executable(Blake2bTests blake2b_test.cxx)
target_link_libraries(Blake2bTests StormByte::Crypto tests)
add_test(NAME Blake2bTests COMMAND Blake2bTests)
set_tests_properties(Blake2bTests PROPERTIES LABELS "hasher")

add_executable(Blake2sTests blake2s_test.cxx)
target_link_libraries(Blake2sTests StormByte::Crypto tests)
add_test(NAME Blake2sTests COMMAND Blake2sTests)
set_tests_properties(Blake2sTests PROPERTIES LABELS "hasher")

add_executable(SHA256Tests sha256_test.cxx)
target_link_libraries(SHA256Tests StormByte::Crypto tests)
add_test(NAME SHA256Tests COMMAND SHA256Tests)
set_tests_properties(SHA256Tests PROPERTIES LABELS "hasher")

add_executable(SHA512Tests sha512_test.cxx)
target_link_libraries(SHA512Tests StormByte::Crypto tests)
add_test(NAME SHA512Tests COMMAND SHA512Tests)
set_tests_properties(SHA512Tests PROPERTIES LABELS "hasher")

add_executable(SHA3Tests sha3_test.cxx)
target_link_libraries(SHA3Tests StormByte::Crypto tests)
add_test(NAME SHA3Tests COMMAND SHA3Tests)
set_tests_properties(SHA3Tests PROPERTIES LABELS "hasher")