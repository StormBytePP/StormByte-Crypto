include(GNUInstallDirs)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

file(GLOB_RECURSE STORMBYTE_CRYPTO_SOURCES CONFIGURE_DEPENDS "${CMAKE_CURRENT_LIST_DIR}/*.cxx")

add_library(StormByte-Crypto SHARED ${STORMBYTE_CRYPTO_SOURCES})
add_library(StormByte::Crypto ALIAS StormByte-Crypto)

set_target_properties(StormByte-Crypto PROPERTIES
	LINKER_LANGUAGE CXX
	SOVERSION ${CMAKE_PROJECT_VERSION}
	VERSION ${CMAKE_PROJECT_VERSION}
	POSITION_INDEPENDENT_CODE ON
	CXX_VISIBILITY_PRESET hidden
	VISIBILITY_INLINES_HIDDEN ON
)

if(MSVC)
	target_compile_options(StormByte-Crypto PRIVATE
		/EHsc
		$<$<CONFIG:Release>:/O2>
		$<$<CONFIG:Debug>:/Od>
	)
	target_compile_definitions(StormByte-Crypto PUBLIC UNICODE NOMINMAX)
else()
	target_compile_options(StormByte-Crypto PRIVATE
		$<$<CONFIG:Debug>:-pipe -g -ggdb -Wall -Wextra -Wnon-virtual-dtor -pedantic -pedantic-errors -O0>
	)
endif()

target_include_directories(StormByte-Crypto
	SYSTEM BEFORE PUBLIC
		"${CMAKE_CURRENT_LIST_DIR}/public"
		"${CMAKE_CURRENT_LIST_DIR}/private"
)
