set(STORMBYTE_BUFFER_SRCDIR "${CMAKE_CURRENT_LIST_DIR}/src")
ensure_build_dir(STORMBYTE_BUFFER_BUILDDIR)
set(STORMBYTE_BUFFER_COMPONENT "StormByte Suite - Buffer")
set(STORMBYTE_BUFFER_OPTIONS
	"-DWITH_STORMBYTE=BUNDLED"
)

# Real MSVC (cl): build Buffer with clang-cl.
# Already clang-cl (or non-MSVC): inherit parent toolchain, no override.
if(CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
	set(STORMBYTE_BUFFER_TOOLCHAIN "clang-cl")
else()
	set(STORMBYTE_BUFFER_TOOLCHAIN "")
endif()

create_cmake_component(
	STORMBYTE_BUFFER_LIBRARY_CREATE_FILE
	"StormByte-Buffer"
	"${STORMBYTE_BUFFER_COMPONENT}"
	"${STORMBYTE_BUFFER_SRCDIR}"
	"${STORMBYTE_BUFFER_BUILDDIR}"
	"${STORMBYTE_BUFFER_OPTIONS}"
	"shared"
	"StormByte-Buffer;StormByte-Logger;StormByte"
	1
	"${STORMBYTE_BUFFER_TOOLCHAIN}"
)
include("${STORMBYTE_BUFFER_LIBRARY_CREATE_FILE}")
add_dependencies(StormByte-Crypto StormByte-Buffer_install)
add_library(StormByte::Buffer ALIAS StormByte-Buffer)