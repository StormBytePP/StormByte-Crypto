add_executable(ECCTests ecc_test.cxx)
target_link_libraries(ECCTests StormByte::Crypto tests)
add_test(NAME ECCTests COMMAND ECCTests)

add_executable(RSAEncryptTests rsa_encrypt_test.cxx)
target_link_libraries(RSAEncryptTests StormByte::Crypto tests)
add_test(NAME RSAEncryptTests COMMAND RSAEncryptTests)