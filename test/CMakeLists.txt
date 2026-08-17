option(ENABLE_TEST "Enable Unit Tests" OFF)
if(ENABLE_TEST)
	enable_testing()

	add_library(tests INTERFACE)
	target_include_directories(tests INTERFACE ${CMAKE_CURRENT_LIST_DIR})

	add_executable(VaultTests vault_test.cxx)
	target_link_libraries(VaultTests StormByte::Crypto tests)
	add_test(NAME Vault COMMAND VaultTests)

	add_executable(PasswordTests password_test.cxx)
	target_link_libraries(PasswordTests StormByte::Crypto tests)
	add_test(NAME Password COMMAND PasswordTests)
	
	add_subdirectory(compressor)
	add_subdirectory(crypter)
	add_subdirectory(hasher)
	add_subdirectory(keypair)
	add_subdirectory(secret)
	add_subdirectory(signer)
endif()