add_executable(ECCTests ecc_test.cxx)
target_link_libraries(ECCTests StormByte::Crypto tests)
add_test(NAME ECCTests COMMAND ECCTests)
set_tests_properties(ECCTests PROPERTIES LABELS "crypter;asymmetric")

add_executable(RSACryptTests rsa_test.cxx)
target_link_libraries(RSACryptTests StormByte::Crypto tests)
add_test(NAME RSACryptTests COMMAND RSACryptTests)
set_tests_properties(RSACryptTests PROPERTIES LABELS "crypter;asymmetric")