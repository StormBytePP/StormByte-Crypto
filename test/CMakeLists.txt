option(ENABLE_TEST "Enable Unit Tests" OFF)
if(ENABLE_TEST AND NOT STORMBYTE_AS_DEPENDENCY)
	add_executable(AESTests aes_test.cxx)
	target_link_libraries(AESTests StormByte::Crypto)
	add_test(NAME AESTests COMMAND AESTests)

	add_executable(Blake2bTests blake2b_test.cxx)
	target_link_libraries(Blake2bTests StormByte::Crypto)
	add_test(NAME Blake2bTests COMMAND Blake2bTests)

	add_executable(Blake2sTests blake2s_test.cxx)
	target_link_libraries(Blake2sTests StormByte::Crypto)
	add_test(NAME Blake2sTests COMMAND Blake2sTests)

	add_executable(Bzip2Tests bzip2_test.cxx)
	target_link_libraries(Bzip2Tests StormByte::Crypto)
	add_test(NAME Bzip2Tests COMMAND Bzip2Tests)

	add_executable(Camellia camellia_test.cxx)
	target_link_libraries(Camellia StormByte::Crypto)
	add_test(NAME Camellia COMMAND Camellia)

	add_executable(DSATests dsa_test.cxx)
	target_link_libraries(DSATests StormByte::Crypto)
	add_test(NAME DSATests COMMAND DSATests)

	add_executable(ECCTests ecc_test.cxx)
	target_link_libraries(ECCTests StormByte::Crypto)
	add_test(NAME ECCTests COMMAND ECCTests)

	add_executable(ECDHTests ecdh_test.cxx)
	target_link_libraries(ECDHTests StormByte::Crypto)
	add_test(NAME ECDHTests COMMAND ECDHTests)

	add_executable(ECDSATests ecdsa_test.cxx)
	target_link_libraries(ECDSATests StormByte::Crypto)
	add_test(NAME ECDSATests COMMAND ECDSATests)

	add_executable(GzipTests gzip_test.cxx)
	target_link_libraries(GzipTests StormByte::Crypto)
	add_test(NAME GzipTests COMMAND GzipTests)

	add_executable(SHA256Tests sha256_test.cxx)
	target_link_libraries(SHA256Tests StormByte::Crypto)
	add_test(NAME SHA256Tests COMMAND SHA256Tests)

	add_executable(SHA512Tests sha512_test.cxx)
	target_link_libraries(SHA512Tests StormByte::Crypto)
	add_test(NAME SHA512Tests COMMAND SHA512Tests)

	add_executable(RSATests rsa_test.cxx)
	target_link_libraries(RSATests StormByte::Crypto)
	add_test(NAME RSATests COMMAND RSATests)
endif()