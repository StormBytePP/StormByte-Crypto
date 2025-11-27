include(GNUInstallDirs)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Sources
file(GLOB_RECURSE STORMBYTE_CONFIG_SOURCES CONFIGURE_DEPENDS "${CMAKE_CURRENT_LIST_DIR}/*.cxx")

# Library
add_library(StormByte-Crypto SHARED ${STORMBYTE_CONFIG_SOURCES})
add_library(StormByte::Crypto ALIAS StormByte-Crypto)
target_link_libraries(StormByte-Crypto PUBLIC StormByte-Buffer)
target_link_libraries(StormByte-Crypto PRIVATE cryptopp)
set_target_properties(StormByte-Crypto PROPERTIES
	LINKER_LANGUAGE CXX
	SOVERSION		${CMAKE_PROJECT_VERSION}
	VERSION 		${CMAKE_PROJECT_VERSION}
)

# Link against the BZip2 library
if (WITH_SYSTEM_BZIP2)
	target_link_libraries(StormByte-Crypto PRIVATE ${BZIP2_LIBRARY_RELEASE})
else()
	target_link_libraries(StormByte-Crypto PRIVATE bz2)
endif()

# Compile options
if(MSVC)
	target_compile_options(StormByte-Crypto PRIVATE /EHsc)
	target_compile_options(StormByte-Crypto PRIVATE $<$<CONFIG:Release>:/O2>)
	target_compile_options(StormByte-Crypto PRIVATE $<$<CONFIG:Debug>:/Od>)
	target_link_options(StormByte-Crypto PRIVATE $<$<CONFIG:Release>:/LTCG /GL>)
else()
	set(CMAKE_CXX_FLAGS_DEBUG "-pipe -g -ggdb -Wall -Wextra -Wnon-virtual-dtor -pedantic -pedantic-errors -O0")
	target_compile_options(StormByte-Crypto PRIVATE -fvisibility=hidden $<$<COMPILE_LANGUAGE:CXX>:-fvisibility-inlines-hidden>)
endif()

# Include directories
target_include_directories(StormByte-Crypto
	SYSTEM BEFORE PUBLIC "${CMAKE_CURRENT_LIST_DIR}/public" "${CMAKE_CURRENT_LIST_DIR}/private"
)

# Install
if (NOT STORMBYTE_AS_DEPENDENCY)
	install(TARGETS StormByte-Crypto
		ARCHIVE 		DESTINATION "${CMAKE_INSTALL_LIBDIR}"
		LIBRARY 		DESTINATION "${CMAKE_INSTALL_LIBDIR}"
		RUNTIME 		DESTINATION ${CMAKE_INSTALL_BINDIR}
	)
	install(DIRECTORY "${CMAKE_CURRENT_LIST_DIR}/public/StormByte/"
		DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/StormByte"
		FILES_MATCHING
		PATTERN "*.h"
		PATTERN "*.hxx"
	)
endif()
