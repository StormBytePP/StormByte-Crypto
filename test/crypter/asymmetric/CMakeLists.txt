add_executable(ECCTests ecc_test.cxx)
target_link_libraries(ECCTests StormByte::Crypto tests)
add_test(NAME ECCTests COMMAND ECCTests)

add_executable(RSATests rsa_test.cxx)
target_link_libraries(RSATests StormByte::Crypto tests)
add_test(NAME RSATests COMMAND RSATests)