cmake_minimum_required(VERSION 3.12)
project(bzip2 VERSION 1.0.8 LANGUAGES C)

set(BZIP2_SRC "${CMAKE_CURRENT_SOURCE_DIR}/src")

add_library(bz2
	"${BZIP2_SRC}/blocksort.c"
	"${BZIP2_SRC}/huffman.c"
	"${BZIP2_SRC}/crctable.c"
	"${BZIP2_SRC}/randtable.c"
	"${BZIP2_SRC}/compress.c"
	"${BZIP2_SRC}/decompress.c"
	"${BZIP2_SRC}/bzlib.c"
)

target_compile_definitions(bz2 PRIVATE _FILE_OFFSET_BITS=64)

target_include_directories(bz2
	PUBLIC
		"$<BUILD_INTERFACE:${BZIP2_SRC}>"
		"$<INSTALL_INTERFACE:include>"
)

set_target_properties(bz2 PROPERTIES
	OUTPUT_NAME bz2
	POSITION_INDEPENDENT_CODE ON
	VERSION ${PROJECT_VERSION}
	SOVERSION 1
)

if(WIN32)
	target_compile_definitions(bz2 PRIVATE _CRT_SECURE_NO_WARNINGS)
	if(BUILD_SHARED_LIBS)
		set_target_properties(bz2 PROPERTIES
			WINDOWS_EXPORT_ALL_SYMBOLS ON
		)
	endif()
endif()

add_library(BZip2::bz2 ALIAS bz2)

include(GNUInstallDirs)

install(TARGETS bz2
	EXPORT bzip2-targets
	ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
	LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
	RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
)

install(FILES "${BZIP2_SRC}/bzlib.h"
	DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
)

install(EXPORT bzip2-targets
	NAMESPACE BZip2::
	DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/bzip2"
)
