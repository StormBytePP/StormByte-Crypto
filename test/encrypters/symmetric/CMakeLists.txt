add_executable(AESGCMTests aes_gcm_test.cxx)
target_link_libraries(AESGCMTests StormByte::Crypto tests)
add_test(NAME AESGCMTests COMMAND AESGCMTests)

add_executable(AESTests aes_test.cxx)
target_link_libraries(AESTests StormByte::Crypto tests)
add_test(NAME AESTests COMMAND AESTests)

add_executable(Camellia camellia_test.cxx)
target_link_libraries(Camellia StormByte::Crypto tests)
add_test(NAME Camellia COMMAND Camellia)

add_executable(ChaCha20Tests chacha20_test.cxx)
target_link_libraries(ChaCha20Tests StormByte::Crypto tests)
add_test(NAME ChaCha20Tests COMMAND ChaCha20Tests)

add_executable(SerpentTests serpent_test.cxx)
target_link_libraries(SerpentTests StormByte::Crypto tests)
add_test(NAME SerpentTests COMMAND SerpentTests)

add_executable(TwofishTests twofish_test.cxx)
target_link_libraries(TwofishTests StormByte::Crypto tests)
add_test(NAME TwofishTests COMMAND TwofishTests)