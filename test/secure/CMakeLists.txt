add_executable(VaultTests vault_test.cxx)
target_link_libraries(VaultTests StormByte::Crypto tests)
add_test(NAME Vault COMMAND VaultTests)
set_tests_properties(Vault PROPERTIES LABELS "security")

add_executable(PasswordTests password_test.cxx)
target_link_libraries(PasswordTests StormByte::Crypto tests)
add_test(NAME Password COMMAND PasswordTests)
set_tests_properties(Password PROPERTIES LABELS "security")
