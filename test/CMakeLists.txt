option(ENABLE_TEST "Enable Unit Tests" OFF)
if(ENABLE_TEST AND NOT STORMBYTE_AS_DEPENDENCY)
	enable_testing()

	add_library(tests INTERFACE)
	target_include_directories(tests INTERFACE ${CMAKE_CURRENT_LIST_DIR})
	
	add_subdirectory(compressors)
	add_subdirectory(encrypters)
	add_subdirectory(hashers)
	add_subdirectory(shared_secret_generators)
	add_subdirectory(signers)
endif()