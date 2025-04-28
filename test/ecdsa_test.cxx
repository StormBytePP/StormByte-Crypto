#include <StormByte/buffer/producer.hxx>
#include <StormByte/crypto/signer.hxx>
#include <StormByte/test_handlers.h>

#include <thread>
#include <iostream>

using namespace StormByte::Crypto;

int TestECDSASignAndVerify() {
	const std::string fn_name = "TestECDSASignAndVerify";
	const std::string message = "This is a test message.";
	const std::string curve_name = "secp256r1";

	// Generate a key pair
	auto keypair_result = KeyPair::Generate(Algorithm::Sign::ECDSA, curve_name);
	ASSERT_TRUE(fn_name, keypair_result.has_value());
	Signer ecdsa(Algorithm::Sign::ECDSA, keypair_result.value());

	// Sign the message
	auto sign_result = ecdsa.Sign(message);
	ASSERT_TRUE(fn_name, sign_result.has_value());
	std::string signature = sign_result.value();

	// Verify the signature
	bool verify_result = ecdsa.Verify(message, signature);
	ASSERT_TRUE(fn_name, verify_result);

	RETURN_TEST(fn_name, 0);
}

int TestECDSAVerifyWithCorruptedSignature() {
	const std::string fn_name = "TestECDSAVerifyWithCorruptedSignature";
	const std::string message = "This is a test message.";
	const std::string curve_name = "secp256r1";

	// Generate a key pair
	auto keypair_result = KeyPair::Generate(Algorithm::Sign::ECDSA, curve_name);
	ASSERT_TRUE(fn_name, keypair_result.has_value());
	Signer ecdsa(Algorithm::Sign::ECDSA, keypair_result.value());

	// Sign the message
	auto sign_result = ecdsa.Sign(message);
	ASSERT_TRUE(fn_name, sign_result.has_value());
	std::string signature = sign_result.value();

	// Corrupt the signature
	if (!signature.empty()) {
		signature[0] = static_cast<char>(~signature[0]);
	}

	// Verify the corrupted signature
	bool verify_result = ecdsa.Verify(message, signature);
	ASSERT_FALSE(fn_name, verify_result);

	RETURN_TEST(fn_name, 0);
}

int TestECDSAVerifyWithMismatchedKey() {
	const std::string fn_name = "TestECDSAVerifyWithMismatchedKey";
	const std::string message = "This is a test message.";
	const std::string curve_name = "secp256r1";

	// Generate two key pairs
	auto keypair_result = KeyPair::Generate(Algorithm::Sign::ECDSA, curve_name);
	ASSERT_TRUE(fn_name, keypair_result.has_value());
	Signer ecdsa(Algorithm::Sign::ECDSA, keypair_result.value());

	auto keypair_result_2 = KeyPair::Generate(Algorithm::Sign::ECDSA, curve_name);
	ASSERT_TRUE(fn_name, keypair_result_2.has_value());
	Signer ecdsa2(Algorithm::Sign::ECDSA, keypair_result_2.value());

	// Sign the message with the first private key
	auto sign_result = ecdsa.Sign(message);
	ASSERT_TRUE(fn_name, sign_result.has_value());
	std::string signature = sign_result.value();

	// Verify the signature with the second public key
	bool verify_result = ecdsa2.Verify(message, signature);
	ASSERT_FALSE(fn_name, verify_result);

	RETURN_TEST(fn_name, 0);
}

int main() {
	int result = 0;

	result += TestECDSASignAndVerify();
	result += TestECDSAVerifyWithCorruptedSignature();
	result += TestECDSAVerifyWithMismatchedKey();

	if (result == 0) {
		std::cout << "All tests passed!" << std::endl;
	} else {
		std::cout << result << " tests failed." << std::endl;
	}
	return result;
}