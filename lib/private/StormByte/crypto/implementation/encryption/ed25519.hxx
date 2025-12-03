#pragma once

#include <StormByte/crypto/implementation/encryption/typedefs.hxx>

/**
 * @namespace Ed25519
 * @brief The namespace containing Ed25519 signing and verification functions.
 */
namespace StormByte::Crypto::Implementation::Encryption::Ed25519 {
	/**
	 * @brief Generates an Ed25519 private/public key pair.
	 * @return ExpectedKeyPair containing the private and public key pair or an error.
	 */
	STORMBYTE_CRYPTO_PRIVATE ExpectedKeyPair GenerateKeyPair() noexcept;

	/**
	 * @brief Signs a message using the Ed25519 private key.
	 * @param message The message to sign.
	 * @param privateKey The Ed25519 private key to use for signing.
	 * @return ExpectedCryptoString containing the signature or an error.
	 */
	STORMBYTE_CRYPTO_PRIVATE ExpectedCryptoString Sign(const std::string& message, const std::string& privateKey) noexcept;

	/**
	 * @brief Signs a buffer using the Ed25519 private key.
	 * @param message The buffer to sign.
	 * @param privateKey The Ed25519 private key to use for signing.
	 * @return ExpectedCryptoBuffer containing the signature or an error.
	 */
	STORMBYTE_CRYPTO_PRIVATE ExpectedCryptoBuffer Sign(const Buffer::FIFO& message, const std::string& privateKey) noexcept;

	/**
	 * @brief Signs data asynchronously using the Consumer/Producer model.
	 * @param consumer The Consumer buffer containing the input data to sign.
	 * @param privateKey The Ed25519 private key to use for signing.
	 * @return A Consumer buffer containing the signature.
	 */
	STORMBYTE_CRYPTO_PRIVATE StormByte::Buffer::Consumer Sign(Buffer::Consumer consumer, const std::string& privateKey) noexcept;

	/**
	 * @brief Verifies a signature using the Ed25519 public key.
	 * @param message The original message.
	 * @param signature The signature to verify.
	 * @param publicKey The Ed25519 public key to use for verification.
	 * @return True if the signature is valid, false otherwise.
	 */
	STORMBYTE_CRYPTO_PRIVATE bool Verify(const std::string& message, const std::string& signature, const std::string& publicKey) noexcept;

	/**
	 * @brief Verifies a signature using the Ed25519 public key.
	 * @param message The buffer containing the original message.
	 * @param signature The signature to verify.
	 * @param publicKey The Ed25519 public key to use for verification.
	 * @return True if the signature is valid, false otherwise.
	 */
	STORMBYTE_CRYPTO_PRIVATE bool Verify(const Buffer::FIFO& message, const std::string& signature, const std::string& publicKey) noexcept;

	/**
	 * @brief Verifies a signature asynchronously using the Consumer/Producer model.
	 * @param consumer The Consumer buffer containing the input data to verify.
	 * @param signature The signature to verify.
	 * @param publicKey The Ed25519 public key to use for verification.
	 * @return True if the signature is valid, false otherwise.
	 */
	STORMBYTE_CRYPTO_PRIVATE bool Verify(Buffer::Consumer consumer, const std::string& signature, const std::string& publicKey) noexcept;
}
