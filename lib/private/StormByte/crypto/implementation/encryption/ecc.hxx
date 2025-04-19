#pragma once

#include <StormByte/crypto/implementation/encryption/typedefs.hxx>

/**
 * @namespace ECC
 * @brief The namespace containing Elliptic Curve Cryptography functions.
 */
namespace StormByte::Crypto::Implementation::Encryption::ECC {
    /**
     * @brief Generates an ECC private/public key pair.
     * @param curve_name The name of the curve to use for key generation (e.g., "secp256r1").
     * @return ExpectedKeyPair containing the private and public key pair or an error.
     */
    STORMBYTE_CRYPTO_PRIVATE ExpectedKeyPair GenerateKeyPair(const std::string& curve_name) noexcept;

    /**
     * @brief Encrypts a message using the ECC public key.
     * @param message The message to encrypt.
     * @param publicKey The ECC public key to use for encryption.
     * @return ExpectedCryptoFutureBuffer containing the encrypted Buffer or an error.
     */
    STORMBYTE_CRYPTO_PRIVATE ExpectedCryptoFutureString Encrypt(const std::string& message, const std::string& publicKey) noexcept;

	/**
     * @brief Encrypts a message using the ECC public key.
     * @param message The message to encrypt.
     * @param publicKey The ECC public key to use for encryption.
     * @return ExpectedCryptoFutureBuffer containing the encrypted Buffer or an error.
     */
    STORMBYTE_CRYPTO_PRIVATE ExpectedCryptoFutureBuffer Encrypt(const Buffers::Simple& message, const std::string& publicKey) noexcept;

	/**
     * @brief Encrypts data asynchronously using the Consumer/Producer model.
     * 
     * @param consumer The Consumer buffer containing the input data.
     * @param publicKey The ECC public key to use for encryption.
     * @return A Consumer buffer containing the encrypted data.
     */
    STORMBYTE_CRYPTO_PRIVATE StormByte::Buffers::Consumer Encrypt(const Buffers::Consumer consumer, const std::string& publicKey) noexcept;

	/**
     * @brief Encrypts a message using the ECC public key.
     * @param message The message to encrypt.
     * @param publicKey The ECC public key to use for encryption.
     * @return ExpectedCryptoFutureBuffer containing the encrypted Buffer or an error.
     */
    STORMBYTE_CRYPTO_PRIVATE ExpectedCryptoFutureString Decrypt(const std::string& message, const std::string& publicKey) noexcept;

    /**
     * @brief Decrypts a message using the ECC private key.
     * @param encryptedBuffer The buffer containing the encrypted data.
     * @param privateKey The ECC private key to use for decryption.
     * @return ExpectedCryptoFutureString containing the decrypted message or an error.
     */
    STORMBYTE_CRYPTO_PRIVATE ExpectedCryptoFutureBuffer Decrypt(const StormByte::Buffers::Simple& encryptedBuffer, const std::string& privateKey) noexcept;

    /**
     * @brief Decrypts data asynchronously using the Consumer/Producer model.
     * 
     * @param consumer The Consumer buffer containing the encrypted data.
     * @param privateKey The ECC private key to use for decryption.
     * @return A Consumer buffer containing the decrypted data.
     */
    STORMBYTE_CRYPTO_PRIVATE StormByte::Buffers::Consumer Decrypt(const Buffers::Consumer consumer, const std::string& privateKey) noexcept;
}