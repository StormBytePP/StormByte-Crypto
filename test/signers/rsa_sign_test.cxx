#include <StormByte/crypto/signer.hxx>
#include <StormByte/test_handlers.h>

#include <iostream>

using namespace StormByte::Crypto;

int TestRSASignVerifySuccess() {
    const std::string fn_name = "TestRSASignVerifySuccess";
    const std::string message = "This is a message to sign.";
    const int key_strength = 2048;

    // Generate a key pair
    auto keypair_result = KeyPair::Generate(Algorithm::Sign::RSA, key_strength);
    ASSERT_TRUE(fn_name, keypair_result.has_value());
    Signer rsa(Algorithm::Sign::RSA, keypair_result.value());

    // Sign the message
    auto sign_result = rsa.Sign(message);
    ASSERT_TRUE(fn_name, sign_result.has_value());
    std::string signature = sign_result.value();

    // Verify the signature
    bool verify_result = rsa.Verify(message, signature);
    ASSERT_TRUE(fn_name, verify_result);

    RETURN_TEST(fn_name, 0);
}

int TestRSASignVerifyWithDifferentKeyPair() {
    const std::string fn_name = "TestRSASignVerifyWithDifferentKeyPair";
    const std::string message = "This is a message to sign.";
    const int key_strength = 2048;

    // Generate two different key pairs
    auto keypair_result = KeyPair::Generate(Algorithm::Sign::RSA, key_strength);
    ASSERT_TRUE(fn_name, keypair_result.has_value());
    Signer rsa(Algorithm::Sign::RSA, keypair_result.value());

    auto keypair_result_2 = KeyPair::Generate(Algorithm::Sign::RSA, key_strength);
    ASSERT_TRUE(fn_name, keypair_result_2.has_value());
    Signer rsa2(Algorithm::Sign::RSA, keypair_result_2.value());

    // Sign the message with the first private key
    auto sign_result = rsa.Sign(message);
    ASSERT_TRUE(fn_name, sign_result.has_value());
    std::string signature = sign_result.value();

    // Verify the signature with the second public key
    bool verify_result = rsa2.Verify(message, signature);
    ASSERT_FALSE(fn_name, verify_result);

    RETURN_TEST(fn_name, 0);
}

int TestRSASignVerifyWithCorruptedMessage() {
    const std::string fn_name = "TestRSASignVerifyWithCorruptedMessage";
    const std::string message = "This is a message to sign.";
    const int key_strength = 2048;

    // Generate a key pair
    auto keypair_result = KeyPair::Generate(Algorithm::Sign::RSA, key_strength);
    ASSERT_TRUE(fn_name, keypair_result.has_value());
    Signer rsa(Algorithm::Sign::RSA, keypair_result.value());

    // Sign the message
    auto sign_result = rsa.Sign(message);
    ASSERT_TRUE(fn_name, sign_result.has_value());
    std::string signature = sign_result.value();

    // Corrupt the message
    std::string corrupted_message = message;
    if (!corrupted_message.empty()) {
        corrupted_message[0] = static_cast<char>(~corrupted_message[0]);
    }

    // Attempt to verify the signature with the corrupted message
    bool verify_result = rsa.Verify(corrupted_message, signature);
    ASSERT_FALSE(fn_name, verify_result);

    RETURN_TEST(fn_name, 0);
}

int main() {
    int result = 0;

    result += TestRSASignVerifySuccess();
    result += TestRSASignVerifyWithDifferentKeyPair();
    result += TestRSASignVerifyWithCorruptedMessage();

    if (result == 0) {
        std::cout << "All tests passed!" << std::endl;
    } else {
        std::cout << result << " tests failed." << std::endl;
    }
    return result;
}
