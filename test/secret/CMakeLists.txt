add_executable(ECDHTests ecdh_test.cxx)
target_link_libraries(ECDHTests StormByte::Crypto tests)
add_test(NAME ECDHTests COMMAND ECDHTests)

add_executable(X25519Tests x25519_test.cxx)
target_link_libraries(X25519Tests StormByte::Crypto tests)
add_test(NAME X25519Tests COMMAND X25519Tests)