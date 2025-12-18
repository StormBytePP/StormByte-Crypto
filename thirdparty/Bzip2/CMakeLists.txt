if(WIN32)
	set(WITH_BZIP2 "BUNDLED" CACHE STRING "Use BZip2 library (SYSTEM/BUNDLED)" FORCE)
else()
	set(WITH_BZIP2 "BUNDLED" CACHE STRING "Use BZip2 library (SYSTEM/BUNDLED)")
endif()
if (WITH_BZIP2 STREQUAL "SYSTEM")
	find_package (BZip2 REQUIRED)
else()
	set(ENABLE_LIB_ONLY ON)
	add_subdirectory(src)
	# Set options for libz2
	set_target_properties(bz2 PROPERTIES
		POSITION_INDEPENDENT_CODE        ON
		CXX_VISIBILITY_PRESET            hidden
	)
	target_include_directories(bz2 INTERFACE $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>)
	set_target_properties(bz2 PROPERTIES OUTPUT_NAME bz2)
	add_library(BZip2::BZip2 ALIAS bz2)
endif()

cmake_policy(SET CMP0079 NEW)
target_link_libraries(StormByte-Crypto PRIVATE BZip2::BZip2)