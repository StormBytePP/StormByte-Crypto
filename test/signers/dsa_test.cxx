#include <StormByte/buffer/producer.hxx>
#include <StormByte/crypto/signer.hxx>
#include <StormByte/test_handlers.h>

#include <thread>
#include <iostream>

using namespace StormByte::Crypto;

int TestDSASignAndVerify(const KeyPair &kp) {
    const std::string fn_name = "TestDSASignAndVerify";
    const std::string message = "This is a test message.";

    Signer dsa(Algorithm::Sign::DSA, kp);

    // Sign the message
    auto sign_result = dsa.Sign(message);
    ASSERT_TRUE(fn_name, sign_result.has_value());
    std::string signature = sign_result.value();

    // Verify the signature
    bool verify_result = dsa.Verify(message, signature);
    ASSERT_TRUE(fn_name, verify_result);

    RETURN_TEST(fn_name, 0);
}

int TestDSAVerifyWithCorruptedSignature(const KeyPair &kp) {
    const std::string fn_name = "TestDSAVerifyWithCorruptedSignature";
    const std::string message = "This is a test message.";

    Signer dsa(Algorithm::Sign::DSA, kp);

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

int TestDSAVerifyWithMismatchedKey(const KeyPair &kp) {
    const std::string fn_name = "TestDSAVerifyWithMismatchedKey";
    const std::string message = "This is a test message.";

    // Use supplied keypair and copy public for mismatch (avoid extra generation)
    Signer dsa(Algorithm::Sign::DSA, kp);
    auto pub = kp.PublicKey();
    auto privOpt = kp.PrivateKey();
    std::string priv = privOpt.has_value() ? *privOpt : std::string();
    if (!pub.empty()) {
        pub[0] = static_cast<char>(~pub[0]);
    }
    Signer dsa2(Algorithm::Sign::DSA, { pub, priv });

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
    const int key_strength = 2048;

    // Generate a single DSA keypair for all tests (key generation is expensive)
    auto keypair_result = KeyPair::Generate(Algorithm::Sign::DSA, key_strength);
    if (!keypair_result.has_value()) {
        std::cerr << "Failed to generate DSA keypair" << std::endl;
        return 1;
    }
    auto kp = keypair_result.value();

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