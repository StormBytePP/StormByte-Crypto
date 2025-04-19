#pragma once

#include <StormByte/crypto/implementation/encryption/typedefs.hxx>

/**
 * @namespace DSA
 * @brief The namespace containing DSA signing and verification functions.
 */
namespace StormByte::Crypto::Implementation::Encryption::DSA {
    /**
     * @brief Generates a DSA private/public key pair.
     * @param keyStrength The strength of the key (e.g., 1024, 2048 bits).
     * @return ExpectedKeyPair containing the private and public key pair or an error.
     */
    STORMBYTE_CRYPTO_PRIVATE ExpectedKeyPair GenerateKeyPair(const int& keyStrength) noexcept;

    /**
     * @brief Signs a message using the DSA private key.
     * @param message The message to sign.
     * @param privateKey The DSA private key to use for signing.
     * @return ExpectedCryptoFutureString containing the signature or an error.
     */
    STORMBYTE_CRYPTO_PRIVATE ExpectedCryptoFutureString Sign(const std::string& message, const std::string& privateKey) noexcept;

    /**
     * @brief Signs a buffer using the DSA private key.
     * @param message The buffer to sign.
     * @param privateKey The DSA private key to use for signing.
     * @return ExpectedCryptoFutureBuffer containing the signature or an error.
     */
    STORMBYTE_CRYPTO_PRIVATE ExpectedCryptoFutureBuffer Sign(const Buffers::Simple& message, const std::string& privateKey) noexcept;

    /**
     * @brief Signs data asynchronously using the Consumer/Producer model.
     * @param consumer The Consumer buffer containing the input data to sign.
     * @param privateKey The DSA private key to use for signing.
     * @return A Consumer buffer containing the signature.
     */
    STORMBYTE_CRYPTO_PRIVATE StormByte::Buffers::Consumer Sign(const Buffers::Consumer consumer, const std::string& privateKey) noexcept;

    /**
     * @brief Verifies a signature using the DSA public key.
     * @param message The original message.
     * @param signature The signature to verify.
     * @param publicKey The DSA public key to use for verification.
     * @return True if the signature is valid, false otherwise.
     */
    STORMBYTE_CRYPTO_PRIVATE bool Verify(const std::string& message, const std::string& signature, const std::string& publicKey) noexcept;

    /**
     * @brief Verifies a signature using the DSA public key.
     * @param message The buffer containing the original message.
     * @param signature The signature to verify.
     * @param publicKey The DSA public key to use for verification.
     * @return True if the signature is valid, false otherwise.
     */
    STORMBYTE_CRYPTO_PRIVATE bool Verify(const Buffers::Simple& message, const std::string& signature, const std::string& publicKey) noexcept;

    /**
     * @brief Verifies a signature asynchronously using the Consumer/Producer model.
     * @param consumer The Consumer buffer containing the input data to verify.
     * @param signature The signature to verify.
     * @param publicKey The DSA public key to use for verification.
     * @return True if the signature is valid, false otherwise.
     */
    STORMBYTE_CRYPTO_PRIVATE bool Verify(const Buffers::Consumer consumer, const std::string& signature, const std::string& publicKey) noexcept;
}