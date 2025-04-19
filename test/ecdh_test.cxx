#include <StormByte/crypto/implementation/encryption/ecdh.hxx>
#include <StormByte/test_handlers.h>

using namespace StormByte::Crypto::Implementation::Encryption;

int TestECDHGenerateKeyPairValidCurve() {
    const std::string fn_name = "TestECDHGenerateKeyPairValidCurve";

    // Generate key pair for a valid curve
    auto keyPair = ECDH::GenerateKeyPair("secp256r1");
    ASSERT_TRUE(fn_name, keyPair.has_value());
    ASSERT_FALSE(fn_name, keyPair->Private.empty());
    ASSERT_FALSE(fn_name, keyPair->Public.empty());

    RETURN_TEST(fn_name, 0);
}

int TestECDHGenerateKeyPairInvalidCurve() {
    const std::string fn_name = "TestECDHGenerateKeyPairInvalidCurve";

    // Attempt to generate key pair for an invalid curve
    auto keyPair = ECDH::GenerateKeyPair("invalid_curve");
    ASSERT_FALSE(fn_name, keyPair.has_value());
    ASSERT_TRUE(fn_name, keyPair.error() != nullptr);

    RETURN_TEST(fn_name, 0);
}

int TestECDHDeriveSharedSecretValidKeys() {
    const std::string fn_name = "TestECDHDeriveSharedSecretValidKeys";

    // Generate key pairs for two parties
    auto keyPair1 = ECDH::GenerateKeyPair("secp256r1");
    auto keyPair2 = ECDH::GenerateKeyPair("secp256r1");

    ASSERT_TRUE(fn_name, keyPair1.has_value());
    ASSERT_TRUE(fn_name, keyPair2.has_value());

    // Derive shared secrets
    auto sharedSecret1 = ECDH::DeriveSharedSecret(keyPair1->Private, keyPair2->Public);
    auto sharedSecret2 = ECDH::DeriveSharedSecret(keyPair2->Private, keyPair1->Public);

    ASSERT_TRUE(fn_name, sharedSecret1.has_value());
    ASSERT_TRUE(fn_name, sharedSecret2.has_value());
    ASSERT_EQUAL(fn_name, sharedSecret1.value(), sharedSecret2.value());

    RETURN_TEST(fn_name, 0);
}

int TestECDHDeriveSharedSecretInvalidPrivateKey() {
    const std::string fn_name = "TestECDHDeriveSharedSecretInvalidPrivateKey";

    // Generate a valid key pair
    auto keyPair = ECDH::GenerateKeyPair("secp256r1");
    ASSERT_TRUE(fn_name, keyPair.has_value());

    // Use an invalid private key
    auto sharedSecret = ECDH::DeriveSharedSecret("invalid_private_key", keyPair->Public);
    ASSERT_FALSE(fn_name, sharedSecret.has_value());
    ASSERT_TRUE(fn_name, sharedSecret.error() != nullptr);

    RETURN_TEST(fn_name, 0);
}

int TestECDHDeriveSharedSecretInvalidPublicKey() {
    const std::string fn_name = "TestECDHDeriveSharedSecretInvalidPublicKey";

    // Generate a valid key pair
    auto keyPair = ECDH::GenerateKeyPair("secp256r1");
    ASSERT_TRUE(fn_name, keyPair.has_value());

    // Use an invalid public key
    auto sharedSecret = ECDH::DeriveSharedSecret(keyPair->Private, "invalid_public_key");
    ASSERT_FALSE(fn_name, sharedSecret.has_value());
    ASSERT_TRUE(fn_name, sharedSecret.error() != nullptr);

    RETURN_TEST(fn_name, 0);
}

int TestECDHGenerateKeyPairDifferentCurves() {
    const std::string fn_name = "TestECDHGenerateKeyPairDifferentCurves";

    // Generate key pairs for different curves
    auto keyPair1 = ECDH::GenerateKeyPair("secp256r1");
    auto keyPair2 = ECDH::GenerateKeyPair("secp384r1");
    auto keyPair3 = ECDH::GenerateKeyPair("secp521r1");

    ASSERT_TRUE(fn_name, keyPair1.has_value());
    ASSERT_TRUE(fn_name, keyPair2.has_value());
    ASSERT_TRUE(fn_name, keyPair3.has_value());

    ASSERT_FALSE(fn_name, keyPair1->Private.empty());
    ASSERT_FALSE(fn_name, keyPair2->Private.empty());
    ASSERT_FALSE(fn_name, keyPair3->Private.empty());

    ASSERT_FALSE(fn_name, keyPair1->Public.empty());
    ASSERT_FALSE(fn_name, keyPair2->Public.empty());
    ASSERT_FALSE(fn_name, keyPair3->Public.empty());

    RETURN_TEST(fn_name, 0);
}

int TestECDHSharedSecretDifferentCurves() {
    const std::string fn_name = "TestECDHSharedSecretDifferentCurves";

    // Generate key pairs for different curves
    auto keyPair1 = ECDH::GenerateKeyPair("secp256r1");
    auto keyPair2 = ECDH::GenerateKeyPair("secp384r1");

    ASSERT_TRUE(fn_name, keyPair1.has_value());
    ASSERT_TRUE(fn_name, keyPair2.has_value());

    // Attempt to derive shared secret between different curves
    auto sharedSecret = ECDH::DeriveSharedSecret(keyPair1->Private, keyPair2->Public);
    ASSERT_FALSE(fn_name, sharedSecret.has_value());
    ASSERT_TRUE(fn_name, sharedSecret.error() != nullptr);

    RETURN_TEST(fn_name, 0);
}

int TestECDHSharedSecretEmptyKeys() {
    const std::string fn_name = "TestECDHSharedSecretEmptyKeys";

    // Attempt to derive shared secret with empty keys
    auto sharedSecret = ECDH::DeriveSharedSecret("", "");
    ASSERT_FALSE(fn_name, sharedSecret.has_value());
    ASSERT_TRUE(fn_name, sharedSecret.error() != nullptr);

    RETURN_TEST(fn_name, 0);
}

int TestECDHSharedSecretCorruptedKeys() {
    const std::string fn_name = "TestECDHSharedSecretCorruptedKeys";

    // Generate a valid key pair
    auto keyPair = ECDH::GenerateKeyPair("secp256r1");
    ASSERT_TRUE(fn_name, keyPair.has_value());

    // Use corrupted keys
    std::string corruptedPrivateKey = keyPair->Private.substr(0, keyPair->Private.size() / 2);
    std::string corruptedPublicKey = keyPair->Public.substr(0, keyPair->Public.size() / 2);

    auto sharedSecret = ECDH::DeriveSharedSecret(corruptedPrivateKey, corruptedPublicKey);
    ASSERT_FALSE(fn_name, sharedSecret.has_value());
    ASSERT_TRUE(fn_name, sharedSecret.error() != nullptr);

    RETURN_TEST(fn_name, 0);
}

int TestECDHServerClientSharedSecret() {
    const std::string fn_name = "TestECDHServerClientSharedSecret";

    // Step 1: Server generates its ECDH key pair
    auto serverKeyPair = ECDH::GenerateKeyPair("secp256r1");
    ASSERT_TRUE(fn_name, serverKeyPair.has_value());
    ASSERT_FALSE(fn_name, serverKeyPair->Private.empty());
    ASSERT_FALSE(fn_name, serverKeyPair->Public.empty());

    // Step 2: Client generates its ECDH key pair
    auto clientKeyPair = ECDH::GenerateKeyPair("secp256r1");
    ASSERT_TRUE(fn_name, clientKeyPair.has_value());
    ASSERT_FALSE(fn_name, clientKeyPair->Private.empty());
    ASSERT_FALSE(fn_name, clientKeyPair->Public.empty());

    // Step 3: Server derives the shared secret using its private key and the client's public key
    auto serverSharedSecret = ECDH::DeriveSharedSecret(serverKeyPair->Private, clientKeyPair->Public);
    ASSERT_TRUE(fn_name, serverSharedSecret.has_value());

    // Step 4: Client derives the shared secret using its private key and the server's public key
    auto clientSharedSecret = ECDH::DeriveSharedSecret(clientKeyPair->Private, serverKeyPair->Public);
    ASSERT_TRUE(fn_name, clientSharedSecret.has_value());

    // Step 5: Verify that both shared secrets are identical
    ASSERT_EQUAL(fn_name, serverSharedSecret.value(), clientSharedSecret.value());

    // Step 6: (Commented) The shared secret can now be used as a secure password for AES encryption/decryption
    // Example:
    // std::string aesPassword = serverSharedSecret.value();
    // Use `aesPassword` for AES encryption/decryption in both server and client.

    RETURN_TEST(fn_name, 0);
}

int main() {
    int result = 0;

    result += TestECDHGenerateKeyPairValidCurve();
    result += TestECDHGenerateKeyPairInvalidCurve();
    result += TestECDHDeriveSharedSecretValidKeys();
    result += TestECDHDeriveSharedSecretInvalidPrivateKey();
    result += TestECDHDeriveSharedSecretInvalidPublicKey();
    result += TestECDHGenerateKeyPairDifferentCurves();
    result += TestECDHSharedSecretDifferentCurves();
    result += TestECDHSharedSecretEmptyKeys();
    result += TestECDHSharedSecretCorruptedKeys();
    result += TestECDHServerClientSharedSecret();

    if (result == 0) {
        std::cout << "All tests passed!" << std::endl;
    } else {
        std::cout << result << " tests failed." << std::endl;
    }
    return result;
}