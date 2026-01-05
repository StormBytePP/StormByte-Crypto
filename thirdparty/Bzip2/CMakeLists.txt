if(WIN32)
	set(WITH_BZIP2 "BUNDLED" CACHE STRING "Use BZip2 library (SYSTEM/BUNDLED)" FORCE)
else()
	set(WITH_BZIP2 "BUNDLED" CACHE STRING "Use BZip2 library (SYSTEM/BUNDLED)")
endif()
if (WITH_BZIP2 STREQUAL "SYSTEM")
	find_package (BZip2 REQUIRED)
else()
	# set(ENABLE_LIB_ONLY ON)
	# add_subdirectory(src)
	# # Set options for libz2
	# set_target_properties(bz2 PROPERTIES
	# 	POSITION_INDEPENDENT_CODE        ON
	# 	CXX_VISIBILITY_PRESET            hidden
	# )
	# target_include_directories(bz2 INTERFACE $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>)
	# if(MSVC)
	# 	set_target_properties(bz2 PROPERTIES OUTPUT_NAME bz2-1) # This is the expected name on Windows
	# else()
	# 	set_target_properties(bz2 PROPERTIES OUTPUT_NAME bz2)
	# endif()
	# add_library(BZip2::BZip2 ALIAS bz2)

	set(BZIP2_SRCDIR "${CMAKE_CURRENT_LIST_DIR}/src")
	ensure_build_dir(BZIP2_BUILDDIR)
	set(BZIP2_COMPONENT "BZip2 Library")
	set(BZIP2_OPTIONS
		"-DENABLE_LIB_ONLY=ON"
		"-DENABLE_STATIC_LIB=ON"
	)
	create_cmake_component(
		BZIP2_LIBRARY_CREATE_FILE
		"BZip2"
		"${BZIP2_COMPONENT}"
		"${BZIP2_SRCDIR}"
		"${BZIP2_BUILDDIR}"
		"${BZIP2_OPTIONS}"
		"static"
		"bz2"
		1
	)
	
	include("${BZIP2_LIBRARY_CREATE_FILE}")

	# Library is called libbz2_static instead of libbz2
	if(MSVC)
		# On Windows, bz2.lib exists and is the IMPLIB for the DLL version, we don't need/want it
		add_custom_command(TARGET BZip2_install POST_BUILD
			COMMAND ${ENV_CMAKE_SILENT_COMMAND} -E remove ${BUILDMASTER_INSTALL_LIBDIR}/bz2.lib
			COMMAND ${ENV_CMAKE_SILENT_COMMAND} -E rename ${BUILDMASTER_INSTALL_LIBDIR}/bz2_static.lib ${BUILDMASTER_INSTALL_LIBDIR}/bz2.lib
			COMMENT "Renaming libbz2_static to libbz2.a for consistency"
		)
	else()
		add_custom_command(TARGET BZip2_install POST_BUILD
			COMMAND ${ENV_CMAKE_SILENT_COMMAND} -E rename ${BUILDMASTER_INSTALL_LIBDIR}/libbz2_static.a ${BUILDMASTER_INSTALL_LIBDIR}/libbz2.a
			COMMENT "Renaming libbz2_static to libbz2.a for consistency"
		)
	endif()

	add_dependencies(StormByte-Crypto BZip2_install)
	add_library(BZip2::BZip2 ALIAS BZip2)
endif()

cmake_policy(SET CMP0079 NEW)
target_link_libraries(StormByte-Crypto PRIVATE BZip2::BZip2)