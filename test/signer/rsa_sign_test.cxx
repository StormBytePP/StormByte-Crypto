#include <StormByte/crypto/signer/rsa.hxx>
#include <StormByte/test_handlers.h>

#include <iostream>

using StormByte::Buffer::FIFO;
using namespace StormByte::Crypto;

int TestRSASignVerifySuccess() {
    const std::string fn_name = "TestRSASignVerifySuccess";
    const std::string message = "This is a message to sign.";
    const int key_strength = 2048;

    // Generate a key pair
    auto keypair_result = KeyPair::RSA::Generate(key_strength);
    ASSERT_TRUE(fn_name, keypair_result);
    Signer::RSA rsa(keypair_result);

    // Sign the message
	FIFO signed_data;
    auto sign_result = rsa.Sign(std::span<const std::byte>(reinterpret_cast<const std::byte*>(message.data()), message.size()), signed_data);
    ASSERT_TRUE(fn_name, sign_result);
    std::string signature = StormByte::String::FromByteVector(signed_data.Data());

    // Verify the signature
    bool verify_result = rsa.Verify(std::span<const std::byte>(reinterpret_cast<const std::byte*>(message.data()), message.size()), signature);
    ASSERT_TRUE(fn_name, verify_result);

    RETURN_TEST(fn_name, 0);
}

int TestRSASignVerifyWithDifferentKeyPair() {
    const std::string fn_name = "TestRSASignVerifyWithDifferentKeyPair";
    const std::string message = "This is a message to sign.";
    const int key_strength = 2048;

    // Generate two different key pairs
    auto keypair_result = KeyPair::RSA::Generate(key_strength);
    ASSERT_TRUE(fn_name, keypair_result);
    Signer::RSA rsa(keypair_result);

    auto keypair_result_2 = KeyPair::RSA::Generate(key_strength);
    ASSERT_TRUE(fn_name, keypair_result_2);
    Signer::RSA rsa2(keypair_result_2);
    // Sign the message with the first private key
	FIFO signed_data;
    auto sign_result = rsa.Sign(std::span<const std::byte>(reinterpret_cast<const std::byte*>(message.data()), message.size()), signed_data);
    ASSERT_TRUE(fn_name, sign_result);
    std::string signature = StormByte::String::FromByteVector(signed_data.Data());

    // Verify the signature with the second public key
    bool verify_result = rsa2.Verify(std::span<const std::byte>(reinterpret_cast<const std::byte*>(message.data()), message.size()), signature);
    ASSERT_FALSE(fn_name, verify_result);

    RETURN_TEST(fn_name, 0);
}

int TestRSASignVerifyWithCorruptedMessage() {
    const std::string fn_name = "TestRSASignVerifyWithCorruptedMessage";
    const std::string message = "This is a message to sign.";
    const int key_strength = 2048;

    // Generate a key pair
    auto keypair_result = KeyPair::RSA::Generate(key_strength);
    ASSERT_TRUE(fn_name, keypair_result);
    Signer::RSA rsa(keypair_result);

    // Sign the message
	FIFO signed_data;
    auto sign_result = rsa.Sign(std::span<const std::byte>(reinterpret_cast<const std::byte*>(message.data()), message.size()), signed_data);
    ASSERT_TRUE(fn_name, sign_result);
    std::string signature = StormByte::String::FromByteVector(signed_data.Data());

    // Corrupt the message
    std::string corrupted_message = message;
    if (!corrupted_message.empty()) {
        corrupted_message[0] = static_cast<char>(~corrupted_message[0]);
    }

    // Attempt to verify the signature with the corrupted message
    bool verify_result = rsa.Verify(std::span<const std::byte>(reinterpret_cast<const std::byte*>(corrupted_message.data()), corrupted_message.size()), signature);
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
