#include <StormByte/buffer/producer.hxx>
#include <StormByte/crypto/signer/dsa.hxx>
#include <StormByte/test_handlers.h>

#include <thread>
#include <iostream>

using StormByte::Buffer::FIFO;
using namespace StormByte::Crypto;

int TestDSASignAndVerify(KeyPair::Generic::PointerType kp) {
    const std::string fn_name = "TestDSASignAndVerify";
    const std::string message = "This is a test message.";

    Signer::DSA dsa(kp);

    // Sign the message
	FIFO signed_data;
    auto sign_result = dsa.Sign(std::span<const std::byte>(reinterpret_cast<const std::byte*>(message.data()), message.size()), signed_data);
    ASSERT_TRUE(fn_name, sign_result);
    std::string signature = StormByte::String::FromByteVector(signed_data.Data());

    // Verify the signature
    bool verify_result = dsa.Verify(std::span<const std::byte>(reinterpret_cast<const std::byte*>(message.data()), message.size()), signature);
    ASSERT_TRUE(fn_name, verify_result);

    RETURN_TEST(fn_name, 0);
}

int TestDSAVerifyWithCorruptedSignature(KeyPair::Generic::PointerType kp) {
    const std::string fn_name = "TestDSAVerifyWithCorruptedSignature";
    const std::string message = "This is a test message.";

    Signer::DSA dsa(kp);

    // Sign the message
	FIFO signed_data;
    auto sign_result = dsa.Sign(std::span<const std::byte>(reinterpret_cast<const std::byte*>(message.data()), message.size()), signed_data);
    ASSERT_TRUE(fn_name, sign_result);
    std::string signature = StormByte::String::FromByteVector(signed_data.Data());

    // Corrupt the signature
    if (!signature.empty()) {
        signature[0] = static_cast<char>(~signature[0]);
    }

    // Verify the corrupted signature
    bool verify_result = dsa.Verify(std::span<const std::byte>(reinterpret_cast<const std::byte*>(message.data()), message.size()), signature);
    ASSERT_FALSE(fn_name, verify_result);

    RETURN_TEST(fn_name, 0);
}

int TestDSAVerifyWithMismatchedKey(KeyPair::Generic::PointerType kp) {
    const std::string fn_name = "TestDSAVerifyWithMismatchedKey";
    const std::string message = "This is a test message.";

    // Use supplied keypair and copy public for mismatch (avoid extra generation)
    Signer::DSA dsa(kp);
    auto pub = kp->PublicKey();
    auto privOpt = kp->PrivateKey();
    std::string priv = privOpt.has_value() ? *privOpt : std::string();
    if (!pub.empty()) {
        pub[0] = static_cast<char>(~pub[0]);
    }
    Signer::DSA dsa2({ pub, priv });

    // Sign the message with the first private key
    FIFO signed_data;
    auto sign_result = dsa.Sign(std::span<const std::byte>(reinterpret_cast<const std::byte*>(message.data()), message.size()), signed_data);
    ASSERT_TRUE(fn_name, sign_result);
    std::string signature = StormByte::String::FromByteVector(signed_data.Data());

    // Verify the signature with the second public key
    bool verify_result = dsa2.Verify(std::span<const std::byte>(reinterpret_cast<const std::byte*>(message.data()), message.size()), signature);
    ASSERT_FALSE(fn_name, verify_result);

    RETURN_TEST(fn_name, 0);
}

int main() {
    int result = 0;
    const int key_strength = 2048;

    // Generate a single DSA keypair for all tests (key generation is expensive)
    auto keypair_result = KeyPair::DSA::Generate(key_strength);
    if (!keypair_result) {
        std::cerr << "Failed to generate DSA keypair" << std::endl;
        return 1;
    }
    auto kp = keypair_result;

    result += TestDSASignAndVerify(kp);
    result += TestDSAVerifyWithCorruptedSignature(kp);
    result += TestDSAVerifyWithMismatchedKey(kp);

    if (result == 0) {
        std::cout << "All tests passed!" << std::endl;
    } else {
        std::cout << result << " tests failed." << std::endl;
    }
    return result;
}