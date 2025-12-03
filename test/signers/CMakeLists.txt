add_executable(DSATests dsa_test.cxx)
target_link_libraries(DSATests StormByte::Crypto tests)
add_test(NAME DSATests COMMAND DSATests)

add_executable(ECDSATests ecdsa_test.cxx)
target_link_libraries(ECDSATests StormByte::Crypto tests)
add_test(NAME ECDSATests COMMAND ECDSATests)

add_executable(Ed25519Tests ed25519_test.cxx)
target_link_libraries(Ed25519Tests StormByte::Crypto tests)
add_test(NAME Ed25519Tests COMMAND Ed25519Tests)

add_executable(RSASignTests rsa_sign_test.cxx)
target_link_libraries(RSASignTests StormByte::Crypto tests)
add_test(NAME RSASignTests COMMAND RSASignTests)