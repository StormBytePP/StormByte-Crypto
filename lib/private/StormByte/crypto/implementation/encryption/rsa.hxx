#pragma once

#include <StormByte/crypto/implementation/encryption/typedefs.hxx>

/**
 * @namespace RSA
 * @brief The namespace containing RSA encryption, decryption, signing, and verification functions.
 */
namespace StormByte::Crypto::Implementation::Encryption::RSA {
	/**
	 * @brief Generates an RSA private/public key pair.
	 * @param keyStrength The strength of the key (e.g., 2048, 4096 bits).
	 * @return ExpectedKeyPair containing the private and public key pair or an error.
	 */
	STORMBYTE_CRYPTO_PRIVATE ExpectedKeyPair GenerateKeyPair(const int& keyStrength) noexcept;

	/**
	 * @brief Encrypts a message using the RSA public key.
	 * @param message The message to encrypt.
	 * @param publicKey The RSA public key to use for encryption.
	 * @return ExpectedCryptoString containing the encrypted message or an error.
	 */
	STORMBYTE_CRYPTO_PRIVATE ExpectedCryptoString Encrypt(const std::string& message, const std::string& publicKey) noexcept;

	/**
	 * @brief Encrypts a buffer using the RSA public key.
	 * @param message The buffer to encrypt.
	 * @param publicKey The RSA public key to use for encryption.
	 * @return ExpectedCryptoBuffer containing the encrypted Buffer or an error.
	 */
	STORMBYTE_CRYPTO_PRIVATE ExpectedCryptoBuffer Encrypt(const Buffer::FIFO& message, const std::string& publicKey) noexcept;

	/**
	 * @brief Encrypts data asynchronously using the Consumer/Producer model.
	 * @param consumer The Consumer buffer containing the input data.
	 * @param publicKey The RSA public key to use for encryption.
	 * @return A Consumer buffer containing the encrypted data.
	 */
	STORMBYTE_CRYPTO_PRIVATE StormByte::Buffer::Consumer Encrypt(const Buffer::Consumer consumer, const std::string& publicKey) noexcept;

	/**
	 * @brief Decrypts a message using the RSA private key.
	 * @param message The encrypted message to decrypt.
	 * @param privateKey The RSA private key to use for decryption.
	 * @return ExpectedCryptoString containing the decrypted message or an error.
	 */
	STORMBYTE_CRYPTO_PRIVATE ExpectedCryptoString Decrypt(const std::string& message, const std::string& privateKey) noexcept;

	/**
	 * @brief Decrypts a buffer using the RSA private key.
	 * @param encryptedBuffer The buffer containing the encrypted data.
	 * @param privateKey The RSA private key to use for decryption.
	 * @return ExpectedCryptoBuffer containing the decrypted Buffer or an error.
	 */
	STORMBYTE_CRYPTO_PRIVATE ExpectedCryptoBuffer Decrypt(const Buffer::FIFO& encryptedBuffer, const std::string& privateKey) noexcept;

	/**
	 * @brief Decrypts data asynchronously using the Consumer/Producer model.
	 * @param consumer The Consumer buffer containing the encrypted data.
	 * @param privateKey The RSA private key to use for decryption.
	 * @return A Consumer buffer containing the decrypted data.
	 */
	STORMBYTE_CRYPTO_PRIVATE StormByte::Buffer::Consumer Decrypt(const Buffer::Consumer consumer, const std::string& privateKey) noexcept;

	/**
	 * @brief Signs a message using the RSA private key.
	 * @param message The message to sign.
	 * @param privateKey The RSA private key to use for signing.
	 * @return ExpectedCryptoString containing the signature or an error.
	 */
	STORMBYTE_CRYPTO_PRIVATE ExpectedCryptoString Sign(const std::string& message, const std::string& privateKey) noexcept;

	/**
	 * @brief Signs a buffer using the RSA private key.
	 * @param message The buffer to sign.
	 * @param privateKey The RSA private key to use for signing.
	 * @return ExpectedCryptoBuffer containing the signature or an error.
	 */
	STORMBYTE_CRYPTO_PRIVATE ExpectedCryptoBuffer Sign(const Buffer::FIFO& message, const std::string& privateKey) noexcept;

	/**
	 * @brief Signs data asynchronously using the Consumer/Producer model.
	 * @param consumer The Consumer buffer containing the input data.
	 * @param privateKey The RSA private key to use for signing.
	 * @return A Consumer buffer containing the signature.
	 */
	STORMBYTE_CRYPTO_PRIVATE StormByte::Buffer::Consumer Sign(const Buffer::Consumer consumer, const std::string& privateKey) noexcept;

	/**
	 * @brief Verifies a signature using the RSA public key.
	 * @param message The original message.
	 * @param signature The signature to verify.
	 * @param publicKey The RSA public key to use for verification.
	 * @return True if the signature is valid, false otherwise.
	 */
	STORMBYTE_CRYPTO_PRIVATE bool Verify(const std::string& message, const std::string& signature, const std::string& publicKey) noexcept;

	/**
	 * @brief Verifies a signature using the RSA public key.
	 * @param message The buffer containing the original message.
	 * @param signature The signature to verify.
	 * @param publicKey The RSA public key to use for verification.
	 * @return True if the signature is valid, false otherwise.
	 */
	STORMBYTE_CRYPTO_PRIVATE bool Verify(const Buffer::FIFO& message, const std::string& signature, const std::string& publicKey) noexcept;

	/**
	 * @brief Verifies a signature asynchronously using the Consumer/Producer model.
	 * @param consumer The Consumer buffer containing the input data.
	 * @param signature The signature to verify.
	 * @param publicKey The RSA public key to use for verification.
	 * @return True if the signature is valid, false otherwise.
	 */
	STORMBYTE_CRYPTO_PRIVATE bool Verify(const Buffer::Consumer consumer, const std::string& signature, const std::string& publicKey) noexcept;
}