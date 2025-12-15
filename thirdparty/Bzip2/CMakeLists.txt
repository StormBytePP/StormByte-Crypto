option(WITH_SYSTEM_BZIP2 "Use the system BZip2 library" ON)
if (WITH_SYSTEM_BZIP2)
	find_package (BZip2 REQUIRED)
else()
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