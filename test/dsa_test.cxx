#include <StormByte/buffer/producer.hxx>
#include <StormByte/crypto/signer.hxx>
#include <StormByte/test_handlers.h>

#include <thread>
#include <iostream>

using namespace StormByte::Crypto;

int TestDSASignAndVerify() {
    const std::string fn_name = "TestDSASignAndVerify";
    const std::string message = "This is a test message.";
    const int key_strength = 2048;

    // Generate a key pair
	auto keypair_result = KeyPair::Generate(Algorithm::Sign::DSA, key_strength);
	if (!keypair_result.has_value()) {
		std::cout << "KeyPair generation failed: " << keypair_result.error()->what() << std::endl;
	}
	ASSERT_TRUE(fn_name, keypair_result.has_value());
	Signer dsa(Algorithm::Sign::DSA, keypair_result.value());

    // Sign the message
    auto sign_result = dsa.Sign(message);
    if (!sign_result.has_value()) {
        std::cout << "Sign failed: " << sign_result.error()->what() << std::endl;
    }
    ASSERT_TRUE(fn_name, sign_result.has_value());
    std::string signature = sign_result.value();
    std::cout << "Signature length: " << signature.size() << std::endl;

    // Verify the signature
    bool verify_result = dsa.Verify(message, signature);
    ASSERT_TRUE(fn_name, verify_result);

    RETURN_TEST(fn_name, 0);
}

int TestDSAVerifyWithCorruptedSignature() {
    const std::string fn_name = "TestDSAVerifyWithCorruptedSignature";
    const std::string message = "This is a test message.";
    const int key_strength = 2048;

    // Generate a key pair
    auto keypair_result = KeyPair::Generate(Algorithm::Sign::DSA, key_strength);
	ASSERT_TRUE(fn_name, keypair_result.has_value());
	Signer dsa(Algorithm::Sign::DSA, keypair_result.value());

    // Sign the message
    auto sign_result = dsa.Sign(message);
    ASSERT_TRUE(fn_name, sign_result.has_value());
    std::string signature = sign_result.value();

    // Corrupt the signature
    if (!signature.empty()) {
        signature[0] = static_cast<char>(~signature[0]);
    }

    // Verify the corrupted signature
    bool verify_result = dsa.Verify(message, signature);
    ASSERT_FALSE(fn_name, verify_result);

    RETURN_TEST(fn_name, 0);
}

int TestDSAVerifyWithMismatchedKey() {
    const std::string fn_name = "TestDSAVerifyWithMismatchedKey";
    const std::string message = "This is a test message.";
    const int key_strength = 2048;

    // Generate two key pairs
    auto keypair_result = KeyPair::Generate(Algorithm::Sign::DSA, key_strength);
	ASSERT_TRUE(fn_name, keypair_result.has_value());
	Signer dsa(Algorithm::Sign::DSA, keypair_result.value());

    auto keypair_result_2 = KeyPair::Generate(Algorithm::Sign::DSA, key_strength);
	ASSERT_TRUE(fn_name, keypair_result_2.has_value());
	Signer dsa2(Algorithm::Sign::DSA, keypair_result_2.value());

    // Sign the message with the first private key
    auto sign_result = dsa.Sign(message);
    ASSERT_TRUE(fn_name, sign_result.has_value());
    std::string signature = sign_result.value();

    // Verify the signature with the second public key
    bool verify_result = dsa2.Verify(message, signature);
    ASSERT_FALSE(fn_name, verify_result);

    RETURN_TEST(fn_name, 0);
}

int main() {
    int result = 0;

    result += TestDSASignAndVerify();
    result += TestDSAVerifyWithCorruptedSignature();
    result += TestDSAVerifyWithMismatchedKey();

	if (result == 0) {
        std::cout << "All tests passed!" << std::endl;
    } else {
        std::cout << result << " tests failed." << std::endl;
    }
    return result;
}