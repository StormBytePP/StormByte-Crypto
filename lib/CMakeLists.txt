include(GNUInstallDirs)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Sources
file(GLOB_RECURSE STORMBYTE_CONFIG_SOURCES CONFIGURE_DEPENDS "${CMAKE_CURRENT_LIST_DIR}/*.cxx")

# Library
add_library(StormByte-Crypto SHARED ${STORMBYTE_CONFIG_SOURCES})
add_library(StormByte::Crypto ALIAS StormByte-Crypto)
set_target_properties(StormByte-Crypto PROPERTIES
	POSITION_INDEPENDENT_CODE        ON
	CXX_VISIBILITY_PRESET            hidden
	VISIBILITY_INLINES_HIDDEN        ON
)
set_target_properties(StormByte-Crypto PROPERTIES
	LINKER_LANGUAGE CXX
	SOVERSION		${CMAKE_PROJECT_VERSION}
	VERSION 		${CMAKE_PROJECT_VERSION}
)

# Compile options
if(MSVC)
	target_compile_options(StormByte-Crypto PRIVATE /EHsc)
	target_compile_options(StormByte-Crypto PRIVATE $<$<CONFIG:Release>:/O2>)
	target_compile_options(StormByte-Crypto PRIVATE $<$<CONFIG:Debug>:/Od>)
	target_compile_definitions(StormByte-Crypto PUBLIC UNICODE NOMINMAX) # Create problems if disabled
else()
	set(CMAKE_CXX_FLAGS_DEBUG "-pipe -g -ggdb -Wall -Wextra -Wnon-virtual-dtor -pedantic -pedantic-errors -O0")
endif()

# Include directories
target_include_directories(StormByte-Crypto
	SYSTEM BEFORE PUBLIC "${CMAKE_CURRENT_LIST_DIR}/public" "${CMAKE_CURRENT_LIST_DIR}/private"
)

