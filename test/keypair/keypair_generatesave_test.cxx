#include <StormByte/crypto/keypair/dsa.hxx>
#include <StormByte/crypto/keypair/ecc.hxx>
#include <StormByte/crypto/keypair/ecdh.hxx>
#include <StormByte/crypto/keypair/ecdsa.hxx>
#include <StormByte/crypto/keypair/ed25519.hxx>
#include <StormByte/crypto/keypair/rsa.hxx>
#include <StormByte/crypto/keypair/x25519.hxx>
#include <StormByte/test_handlers.h>

using namespace StormByte::Crypto;

int dsa() {
	const std::string fn_name = "dsa";
	auto keypair_dsa = KeyPair::DSA::Generate(2048);
	ASSERT_TRUE(fn_name, keypair_dsa);
	auto created = keypair_dsa->Save("/tmp", "dsa_test_keypair");
	ASSERT_TRUE(fn_name, created);
	RETURN_TEST(fn_name, 0);
}

int main() {
	int result = 0;

	//result += dsa();

	if (result == 0) {
		std::cout << "All tests passed!" << std::endl;
	} else {
		std::cout << result << " tests failed." << std::endl;
	}
	return result;
}