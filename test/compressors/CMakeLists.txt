add_executable(Bzip2Tests bzip2_test.cxx)
target_link_libraries(Bzip2Tests StormByte::Crypto tests)
add_test(NAME Bzip2Tests COMMAND Bzip2Tests)

add_executable(GzipTests gzip_test.cxx)
target_link_libraries(GzipTests StormByte::Crypto tests)
add_test(NAME GzipTests COMMAND GzipTests)

add_executable(ZlibTests zlib_test.cxx)
target_link_libraries(ZlibTests StormByte::Crypto tests)
add_test(NAME ZlibTests COMMAND ZlibTests)