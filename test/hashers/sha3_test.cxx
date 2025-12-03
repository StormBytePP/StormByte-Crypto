#include <StormByte/crypto/hasher.hxx>
#include <StormByte/test_handlers.h>

#include <iostream>

using namespace StormByte::Crypto;

int TestSHA3_256Hash() {
	const std::string fn_name = "TestSHA3_256Hash";
	const std::string input = "The quick brown fox jumps over the lazy dog";
	const std::string expected = "69070DDA01975C8C120C3AADA1B282394E7F032FA9CF32F4CB2259A0897DFC04";

	Hasher hasher(Algorithm::Hash::SHA3_256);
	auto result = hasher.Hash(input);

	ASSERT_TRUE(fn_name, result.has_value());
	ASSERT_EQUAL(fn_name, expected, result.value());

	RETURN_TEST(fn_name, 0);
}

int TestSHA3_512Hash() {
	const std::string fn_name = "TestSHA3_512Hash";
	const std::string input = "The quick brown fox jumps over the lazy dog";
	const std::string expected = "01DEDD5DE4EF14642445BA5F5B97C15E47B9AD931326E4B0727CD94CEFC44FFF23F07BF543139939B49128CAF436DC1BDEE54FCB24023A08D9403F9B4BF0D450";

	Hasher hasher(Algorithm::Hash::SHA3_512);
	auto result = hasher.Hash(input);

	ASSERT_TRUE(fn_name, result.has_value());
	ASSERT_EQUAL(fn_name, expected, result.value());

	RETURN_TEST(fn_name, 0);
}

int main(int, char**) {
	int result = 0;

	result += TestSHA3_256Hash();
	result += TestSHA3_512Hash();

	if (result == 0) {
		std::cout << "SHA-3 tests passed" << std::endl;
	} else {
		std::cout << "SHA-3 tests failed" << std::endl;
	}
	return result;
}
