#pragma once

#include <StormByte/crypto/implementation/encryption/typedefs.hxx>

namespace StormByte::Crypto::Implementation::Encryption::AES_GCM {
/**
 * @brief Encrypts a string using AES-GCM (Galois/Counter Mode).
 * @param data The string to encrypt.
 * @param password The password to use for encryption.
 * @return ExpectedCryptoBuffer containing the encrypted data or an error.
 */
ExpectedCryptoBuffer Encrypt(const std::string& data, const std::string& password) noexcept;	/**
	 * @brief Encrypts data from a Buffer::FIFO buffer using AES-GCM.
	 * @param data The Buffer::FIFO buffer containing data to encrypt.
	 * @param password The password to use for encryption.
	 * @return ExpectedCryptoBuffer containing the encrypted data or an error.
	 */
	ExpectedCryptoBuffer Encrypt(const Buffer::FIFO& data, const std::string& password) noexcept;

	/**
	 * @brief Encrypts data from a Buffer::Consumer asynchronously using AES-GCM.
	 * @param Buffer::Consumer The Buffer::Consumer to read data from.
	 * @param password The password to use for encryption.
	 * @return A Buffer::Consumer that will contain the encrypted data.
	 */
	Buffer::Consumer Encrypt(const Buffer::Consumer consumer, const std::string& password) noexcept;

/**
 * @brief Decrypts a string using AES-GCM.
 * @param encryptedData The encrypted string to decrypt.
 * @param password The password to use for decryption.
 * @return ExpectedCryptoBuffer containing the decrypted data or an error.
 */
ExpectedCryptoBuffer Decrypt(const std::string& encryptedData, const std::string& password) noexcept;	/**
	 * @brief Decrypts data from a Buffer::FIFO buffer using AES-GCM.
	 * @param encryptedData The Buffer::FIFO buffer containing encrypted data.
	 * @param password The password to use for decryption.
	 * @return ExpectedCryptoBuffer containing the decrypted data or an error.
	 */
	ExpectedCryptoBuffer Decrypt(const Buffer::FIFO& encryptedData, const std::string& password) noexcept;

	/**
	 * @brief Decrypts data from a Buffer::Consumer asynchronously using AES-GCM.
	 * @param Buffer::Consumer The Buffer::Consumer to read encrypted data from.
	 * @param password The password to use for decryption.
	 * @return A Buffer::Consumer that will contain the decrypted data.
	 */
	Buffer::Consumer Decrypt(const Buffer::Consumer consumer, const std::string& password) noexcept;

	/**
	 * @brief Generates a random password for AES-GCM.
	 * @param size The size of the password in bytes (default: 32).
	 * @return ExpectedCryptoString containing the generated password or an error.
	 */
	ExpectedCryptoString RandomPassword(size_t size = 32) noexcept;
}
