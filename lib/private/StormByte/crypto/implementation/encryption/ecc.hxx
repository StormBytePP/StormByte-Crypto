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
	 * @return ExpectedCryptoBuffer containing the encrypted Buffer or an error.
	 */
	STORMBYTE_CRYPTO_PRIVATE ExpectedCryptoString Encrypt(const std::string& message, const std::string& publicKey) noexcept;

	/**
	 * @brief Encrypts a message using the ECC public key.
	 * @param message The message to encrypt.
	 * @param publicKey The ECC public key to use for encryption.
	 * @return ExpectedCryptoBuffer containing the encrypted Buffer or an error.
	 */
	STORMBYTE_CRYPTO_PRIVATE ExpectedCryptoBuffer Encrypt(const Buffer::FIFO& message, const std::string& publicKey) noexcept;

	/**
	 * @brief Encrypts data asynchronously using the Consumer/Producer model.
	 * 
	 * @param consumer The Consumer buffer containing the input data.
	 * @param publicKey The ECC public key to use for encryption.
	 * @return A Consumer buffer containing the encrypted data.
	 */
	STORMBYTE_CRYPTO_PRIVATE StormByte::Buffer::Consumer Encrypt(const Buffer::Consumer consumer, const std::string& publicKey) noexcept;

	/**
	 * @brief Encrypts a message using the ECC public key.
	 * @param message The message to encrypt.
	 * @param publicKey The ECC public key to use for encryption.
	 * @return ExpectedCryptoBuffer containing the encrypted Buffer or an error.
	 */
	STORMBYTE_CRYPTO_PRIVATE ExpectedCryptoString Decrypt(const std::string& message, const std::string& publicKey) noexcept;

	/**
	 * @brief Decrypts a message using the ECC private key.
	 * @param encryptedBuffer The buffer containing the encrypted data.
	 * @param privateKey The ECC private key to use for decryption.
	 * @return ExpectedCryptoString containing the decrypted message or an error.
	 */
	STORMBYTE_CRYPTO_PRIVATE ExpectedCryptoBuffer Decrypt(const StormByte::Buffer::FIFO& encryptedBuffer, const std::string& privateKey) noexcept;

	/**
	 * @brief Decrypts data asynchronously using the Consumer/Producer model.
	 * 
	 * @param consumer The Consumer buffer containing the encrypted data.
	 * @param privateKey The ECC private key to use for decryption.
	 * @return A Consumer buffer containing the decrypted data.
	 */
	STORMBYTE_CRYPTO_PRIVATE StormByte::Buffer::Consumer Decrypt(const Buffer::Consumer consumer, const std::string& privateKey) noexcept;
}