#pragma once

#include <StormByte/crypto/implementation/encryption/typedefs.hxx>

/**
 * @namespace ECDSA
 * @brief The namespace containing ECDSA signing and verification functions.
 */
namespace StormByte::Crypto::Implementation::Encryption::ECDSA {
	/**
	 * @brief Generates an ECDSA private/public key pair.
	 * @param curveName The name of the elliptic curve (e.g., "secp256r1").
	 * @return ExpectedKeyPair containing the private and public key pair or an error.
	 */
	STORMBYTE_CRYPTO_PRIVATE ExpectedKeyPair GenerateKeyPair(const std::string& curveName) noexcept;

	/**
	 * @brief Signs a message using the ECDSA private key.
	 * @param message The message to sign.
	 * @param privateKey The ECDSA private key to use for signing.
	 * @return ExpectedCryptoFutureString containing the signature or an error.
	 */
	STORMBYTE_CRYPTO_PRIVATE ExpectedCryptoFutureString Sign(const std::string& message, const std::string& privateKey) noexcept;

	/**
	 * @brief Signs a buffer using the ECDSA private key.
	 * @param message The buffer to sign.
	 * @param privateKey The ECDSA private key to use for signing.
	 * @return ExpectedCryptoFutureBuffer containing the signature or an error.
	 */
	STORMBYTE_CRYPTO_PRIVATE ExpectedCryptoFutureBuffer Sign(const Buffer::Simple& message, const std::string& privateKey) noexcept;

	/**
	 * @brief Signs data asynchronously using the Consumer/Producer model.
	 * @param consumer The Consumer buffer containing the input data to sign.
	 * @param privateKey The ECDSA private key to use for signing.
	 * @return A Consumer buffer containing the signature.
	 */
	STORMBYTE_CRYPTO_PRIVATE StormByte::Buffer::Consumer Sign(const Buffer::Consumer consumer, const std::string& privateKey) noexcept;

	/**
	 * @brief Verifies a signature using the ECDSA public key.
	 * @param message The original message.
	 * @param signature The signature to verify.
	 * @param publicKey The ECDSA public key to use for verification.
	 * @return True if the signature is valid, false otherwise.
	 */
	STORMBYTE_CRYPTO_PRIVATE bool Verify(const std::string& message, const std::string& signature, const std::string& publicKey) noexcept;

	/**
	 * @brief Verifies a signature using the ECDSA public key.
	 * @param message The buffer containing the original message.
	 * @param signature The signature to verify.
	 * @param publicKey The ECDSA public key to use for verification.
	 * @return True if the signature is valid, false otherwise.
	 */
	STORMBYTE_CRYPTO_PRIVATE bool Verify(const Buffer::Simple& message, const std::string& signature, const std::string& publicKey) noexcept;

	/**
	 * @brief Verifies a signature asynchronously using the Consumer/Producer model.
	 * @param consumer The Consumer buffer containing the input data to verify.
	 * @param signature The signature to verify.
	 * @param publicKey The ECDSA public key to use for verification.
	 * @return True if the signature is valid, false otherwise.
	 */
	STORMBYTE_CRYPTO_PRIVATE bool Verify(const Buffer::Consumer consumer, const std::string& signature, const std::string& publicKey) noexcept;
}