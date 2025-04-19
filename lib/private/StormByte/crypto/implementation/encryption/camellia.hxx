#pragma once

#include <StormByte/crypto/implementation/encryption/typedefs.hxx>

/**
 * @namespace Camellia
 * @brief The namespace containing Camellia encryption functions.
 */
namespace StormByte::Crypto::Implementation::Encryption::Camellia {
    /**
     * @brief Encrypts a string using Camellia.
     * @param input The string to encrypt.
     * @param password The password to use for encryption.
     * @return Expected<FutureBuffer, CryptoException> containing the encrypted Buffer or an error.
     */
    STORMBYTE_CRYPTO_PRIVATE ExpectedCryptoFutureBuffer Encrypt(const std::string& input, const std::string& password) noexcept;

    /**
     * @brief Encrypts a Buffer using Camellia.
     * @param input The Buffer to encrypt.
     * @param password The password to use for encryption.
     * @return Expected<FutureBuffer, CryptoException> containing the encrypted Buffer or an error.
     */
    STORMBYTE_CRYPTO_PRIVATE ExpectedCryptoFutureBuffer Encrypt(const StormByte::Buffers::Simple& input, const std::string& password) noexcept;

	/**
     * @brief Encrypts data asynchronously using the Consumer/Producer model.
     * 
     * @param consumer The Consumer buffer containing the input data.
     * @param password The password to use for encryption.
     * @return A Consumer buffer containing the encrypted data.
     */
    STORMBYTE_CRYPTO_PRIVATE StormByte::Buffers::Consumer Encrypt(const Buffers::Consumer consumer, const std::string& password) noexcept;

    /**
     * @brief Decrypts a string using Camellia.
     * @param input The string to decrypt.
     * @param password The password to use for decryption.
     * @return Expected<FutureBuffer, CryptoException> containing the decrypted Buffer or an error.
     */
    STORMBYTE_CRYPTO_PRIVATE ExpectedCryptoFutureBuffer Decrypt(const std::string& input, const std::string& password) noexcept;

    /**
     * @brief Decrypts a Buffer using Camellia.
     * @param input The Buffer to decrypt.
     * @param password The password to use for decryption.
     * @return Expected<FutureBuffer, CryptoException> containing the decrypted Buffer or an error.
     */
    STORMBYTE_CRYPTO_PRIVATE ExpectedCryptoFutureBuffer Decrypt(const StormByte::Buffers::Simple& input, const std::string& password) noexcept;

	/**
     * @brief Decrypts data asynchronously using the Consumer/Producer model.
     * 
     * @param consumer The Consumer buffer containing the encrypted data.
     * @param password The password to use for decryption.
     * @return A Consumer buffer containing the decrypted data.
     */
    STORMBYTE_CRYPTO_PRIVATE StormByte::Buffers::Consumer Decrypt(const Buffers::Consumer consumer, const std::string& password) noexcept;

    /**
     * @brief Generates a random password.
     * @param passwordSize The size of the password to generate.
     * @return The generated password.
     */
    STORMBYTE_CRYPTO_PRIVATE ExpectedCryptoFutureString RandomPassword(const size_t& passwordSize = 16) noexcept;
}