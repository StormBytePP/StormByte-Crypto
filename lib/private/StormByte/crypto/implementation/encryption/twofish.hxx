#pragma once

#include <StormByte/crypto/implementation/encryption/typedefs.hxx>

/**
 * @namespace Twofish
 * @brief The namespace containing Twofish encryption functions.
 */
namespace StormByte::Crypto::Implementation::Encryption::Twofish {
	/**
	 * @brief Encrypts a string using Twofish.
	 * @param input The string to encrypt.
	 * @param password The password to use for encryption.
	 * @return Expected<FutureBuffer, CryptoException> containing the encrypted Buffer or an error.
	 */
	STORMBYTE_CRYPTO_PRIVATE ExpectedCryptoBuffer Encrypt(const std::string& input, const std::string& password) noexcept;

	/**
	 * @brief Encrypts a Buffer using Twofish.
	 * @param input The Buffer to encrypt.
	 * @param password The password to use for encryption.
	 * @return Expected<FutureBuffer, CryptoException> containing the encrypted Buffer or an error.
	 */
	STORMBYTE_CRYPTO_PRIVATE ExpectedCryptoBuffer Encrypt(const StormByte::Buffer::FIFO& input, const std::string& password) noexcept;

	/**
	 * @brief Encrypts data asynchronously using the Consumer/Producer model.
	 * 
	 * @param consumer The Consumer buffer containing the input data.
	 * @param password The password to use for encryption.
	 * @return A Consumer buffer containing the encrypted data.
	 */
	STORMBYTE_CRYPTO_PRIVATE StormByte::Buffer::Consumer Encrypt(const Buffer::Consumer consumer, const std::string& password) noexcept;

	/**
	 * @brief Decrypts a string using Twofish.
	 * @param input The string to decrypt.
	 * @param password The password to use for decryption.
	 * @return Expected<FutureBuffer, CryptoException> containing the decrypted Buffer or an error.
	 */
	STORMBYTE_CRYPTO_PRIVATE ExpectedCryptoBuffer Decrypt(const std::string& input, const std::string& password) noexcept;

	/**
	 * @brief Decrypts data asynchronously using the Consumer/Producer model.
	 * 
	 * @param consumer The Consumer buffer containing the encrypted data.
	 * @param password The password to use for decryption.
	 * @return A Consumer buffer containing the decrypted data.
	 */
	STORMBYTE_CRYPTO_PRIVATE StormByte::Buffer::Consumer Decrypt(const Buffer::Consumer consumer, const std::string& password) noexcept;

	/**
	 * @brief Decrypts a Buffer using Twofish.
	 * @param input The Buffer to decrypt.
	 * @param password The password to use for decryption.
	 * @return Expected<FutureBuffer, CryptoException> containing the decrypted Buffer or an error.
	 */
	STORMBYTE_CRYPTO_PRIVATE ExpectedCryptoBuffer Decrypt(const StormByte::Buffer::FIFO& input, const std::string& password) noexcept;

	/**
	 * @brief Generates a random password.
	 * @param passwordSize The size of the password to generate.
	 * @return The generated password.
	 */
	STORMBYTE_CRYPTO_PRIVATE ExpectedCryptoString RandomPassword(const size_t& passwordSize = 16) noexcept;
}
