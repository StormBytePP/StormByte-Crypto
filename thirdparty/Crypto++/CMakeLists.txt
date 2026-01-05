if (WIN32)
	set(WITH_CRYPTOPP "BUNDLED" CACHE STRING "Use Crypto++ library (SYSTEM/BUNDLED)" FORCE)
else()
	set(WITH_CRYPTOPP "BUNDLED" CACHE STRING "Use Crypto++ library (SYSTEM/BUNDLED)")
endif()
if (WITH_CRYPTOPP STREQUAL "SYSTEM")
	set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake")
	find_package(Crypto++ REQUIRED)
else()
	# set(CRYPTOPP_BUILD_TESTING OFF)
	# set(CRYPTOPP_DEFAULT_BUILD_TYPE "Release")
	# add_subdirectory(cryptopp-cmake)
	# add_library(CryptoPP::CryptoPP ALIAS cryptopp)
	# if (MSVC)
	# 	target_compile_definitions(cryptopp PRIVATE _SILENCE_ALL_MS_EXT_DEPRECATION_WARNINGS)
	# else()
	# 	target_compile_options(cryptopp PRIVATE -fno-strict-aliasing)
	# endif()


	set(CRYPTOPP_SRCDIR "${CMAKE_CURRENT_LIST_DIR}/cryptopp-cmake")
	ensure_build_dir(CRYPTOPP_BUILDDIR)
	set(CRYPTOPP_COMPONENT "Crypto++ Library")
	set(CRYPTOPP_OPTIONS
		"-DCRYPTOPP_BUILD_TESTING=OFF"
		"-DCRYPTOPP_DEFAULT_BUILD_TYPE=Release"
	)
	create_cmake_component(
		CRYPTOPP_LIBRARY_CREATE_FILE
		"CryptoPP"
		"${CRYPTOPP_COMPONENT}"
		"${CRYPTOPP_SRCDIR}"
		"${CRYPTOPP_BUILDDIR}"
		"${CRYPTOPP_OPTIONS}"
		"static"
		"cryptopp"
		1
	)
	include("${CRYPTOPP_LIBRARY_CREATE_FILE}")
	add_dependencies(StormByte-Crypto CryptoPP_install)
	add_library(CryptoPP::CryptoPP ALIAS CryptoPP)
	target_include_directories(CryptoPP SYSTEM INTERFACE ${BUILDMASTER_INSTALL_INCLUDEDIR}/cryptopp)
endif()

cmake_policy(SET CMP0079 NEW)
target_link_libraries(StormByte-Crypto PRIVATE CryptoPP::CryptoPP)