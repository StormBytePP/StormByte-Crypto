if(WIN32)
	set(WITH_BZIP2 "BUNDLED" CACHE STRING "Use BZip2 library (SYSTEM/BUNDLED)" FORCE)
else()
	set(WITH_BZIP2 "BUNDLED" CACHE STRING "Use BZip2 library (SYSTEM/BUNDLED)")
endif()

if(WITH_BZIP2 STREQUAL "SYSTEM")
	find_package(BZip2 REQUIRED)
else()
	buildmaster_component(
		bz2
		"BZip2 Compression Library"
		"${CMAKE_CURRENT_LIST_DIR}/cmake-port"
		"ENABLE_LIB_ONLY=ON;ENABLE_APP=OFF;ENABLE_EXAMPLES=OFF;ENABLE_DOCS=OFF;ENABLE_SHARED_LIB=OFF;ENABLE_STATIC_LIB=ON"
		static
		"bz2"
		"ALIAS=BZip2::BZip2"
	)
endif()

buildmaster_link(StormByte-Crypto BZip2::BZip2)
