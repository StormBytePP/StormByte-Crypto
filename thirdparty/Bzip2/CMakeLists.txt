if(WIN32)
	set(WITH_BZIP2 "BUNDLED" CACHE STRING "Use BZip2 library (SYSTEM/BUNDLED)" FORCE)
else()
	set(WITH_BZIP2 "BUNDLED" CACHE STRING "Use BZip2 library (SYSTEM/BUNDLED)")
endif()

if(WITH_BZIP2 STREQUAL "SYSTEM")
	find_package(BZip2 REQUIRED)
else()
	set(BZIP2_SRC_DIR "${CMAKE_CURRENT_LIST_DIR}/src")
	ensure_build_dir(BZIP2_BUILD_DIR)
	set(BZIP2_COMPONENT "BZip2 Compression Library")

	set(BZIP2_OPTIONS
		-DENABLE_LIB_ONLY=ON
		-DENABLE_APP=OFF
		-DENABLE_EXAMPLES=OFF
		-DENABLE_DOCS=OFF
		-DENABLE_SHARED_LIB=OFF
		-DENABLE_STATIC_LIB=ON
	)

	create_cmake_component(
		BZIP2_LIBRARY_CREATE_FILE
		"bz2"
		"${BZIP2_COMPONENT}"
		"${BZIP2_SRC_DIR}"
		"${BZIP2_BUILD_DIR}"
		"${BZIP2_OPTIONS}"
		"static"
		"bz2"
		1
	)
	include("${BZIP2_LIBRARY_CREATE_FILE}")

	# Rename the static library to the canonical name after install
	if(MSVC)
		# On Windows the static lib is named bz2_static.lib
		add_custom_command(TARGET bz2_install POST_BUILD
			COMMAND ${ENV_CMAKE_SILENT_COMMAND} -E remove -f "${BUILDMASTER_INSTALL_LIBDIR}/bz2.lib"
			COMMAND ${ENV_CMAKE_SILENT_COMMAND} -E copy
				"${BUILDMASTER_INSTALL_LIBDIR}/bz2_static.lib"
				"${BUILDMASTER_INSTALL_LIBDIR}/bz2.lib"
			COMMENT "Renaming bz2_static.lib → bz2.lib"
			VERBATIM
		)
	else()
		add_custom_command(TARGET bz2_install POST_BUILD
			COMMAND ${ENV_CMAKE_SILENT_COMMAND} -E copy
				"${BUILDMASTER_INSTALL_LIBDIR}/libbz2_static.a"
				"${BUILDMASTER_INSTALL_LIBDIR}/libbz2.a"
			COMMENT "Renaming libbz2_static.a → libbz2.a"
			VERBATIM
		)
	endif()

	# Create the same imported target that find_package(BZip2) provides
	if(NOT TARGET BZip2::BZip2)
		add_library(BZip2::BZip2 ALIAS bz2)
	endif()
endif()

target_link_libraries(StormByte-Crypto PRIVATE BZip2::BZip2)