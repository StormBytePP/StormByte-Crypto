if(MSVC)
	set(STORMBYTE_BUFFER_OPTSTR "TOOLCHAIN=clang-cl;ALIAS=StormByte::Buffer")
else()
	set(STORMBYTE_BUFFER_OPTSTR "ALIAS=StormByte::Buffer")
endif()

if(BUILD_SHARED_LIBS)
	set(STORMBYTE_BUFFER_MODE shared)
else()
	set(STORMBYTE_BUFFER_MODE static)
endif()

buildmaster_component(
	StormByte-Buffer
	"StormByte Suite - Buffer"
	"${CMAKE_CURRENT_LIST_DIR}/src"
	"WITH_STORMBYTE=BUNDLED;ENABLE_TEST=OFF"
	${STORMBYTE_BUFFER_MODE}
	"StormByte-Buffer"
	"${STORMBYTE_BUFFER_OPTSTR}"
)
