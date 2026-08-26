if(WIN32)
	set(WITH_CRYPTOPP "BUNDLED" CACHE STRING "Use Crypto++ library (SYSTEM/BUNDLED)" FORCE)
else()
	set(WITH_CRYPTOPP "BUNDLED" CACHE STRING "Use Crypto++ library (SYSTEM/BUNDLED)")
endif()

if(WITH_CRYPTOPP STREQUAL "SYSTEM")
	set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake")
	find_package(Crypto++ REQUIRED)
else()
	buildmaster_component(
		CryptoPP
		"Crypto++ Library"
		"${CMAKE_CURRENT_LIST_DIR}/cmake-port"
		""
		static
		"cryptopp"
		"ALIAS=CryptoPP::CryptoPP;GIT={RESET;PATCH=${CMAKE_CURRENT_LIST_DIR}/0001-msvc-drop-stdext.patch;TITLE=MSVC drop stdext;ROOT=src}"
	)

	target_include_directories(CryptoPP SYSTEM INTERFACE
		${BUILDMASTER_INSTALL_INCLUDEDIR}/cryptopp
	)
endif()

buildmaster_link(StormByte-Crypto CryptoPP::CryptoPP)
