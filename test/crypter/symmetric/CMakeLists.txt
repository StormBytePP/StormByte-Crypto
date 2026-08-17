add_executable(AESGCMTests aes_gcm_test.cxx)
target_link_libraries(AESGCMTests StormByte::Crypto tests)
add_test(NAME AESGCMTests COMMAND AESGCMTests)
set_tests_properties(AESGCMTests PROPERTIES LABELS "crypter;symmetric")

add_executable(AESTests aes_test.cxx)
target_link_libraries(AESTests StormByte::Crypto tests)
add_test(NAME AESTests COMMAND AESTests)
set_tests_properties(AESTests PROPERTIES LABELS "crypter;symmetric")

add_executable(CamelliaTests camellia_test.cxx)
target_link_libraries(CamelliaTests StormByte::Crypto tests)
add_test(NAME CamelliaTests COMMAND CamelliaTests)
set_tests_properties(CamelliaTests PROPERTIES LABELS "crypter;symmetric")

add_executable(ChaChaPolyTests chachapoly_test.cxx)
target_link_libraries(ChaChaPolyTests StormByte::Crypto tests)
add_test(NAME ChaChaPolyTests COMMAND ChaChaPolyTests)
set_tests_properties(ChaChaPolyTests PROPERTIES LABELS "crypter;symmetric")

add_executable(SerpentTests serpent_test.cxx)
target_link_libraries(SerpentTests StormByte::Crypto tests)
add_test(NAME SerpentTests COMMAND SerpentTests)
set_tests_properties(SerpentTests PROPERTIES LABELS "crypter;symmetric")

add_executable(TwofishTests twofish_test.cxx)
target_link_libraries(TwofishTests StormByte::Crypto tests)
add_test(NAME TwofishTests COMMAND TwofishTests)
set_tests_properties(TwofishTests PROPERTIES LABELS "crypter;symmetric")