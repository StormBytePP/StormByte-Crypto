#pragma once

#include <StormByte/crypto/implementation/encryption/typedefs.hxx>

/**
 * @namespace ECDH
 * @brief The namespace containing Elliptic Curve Diffie-Hellman key exchange functions.
 */
namespace StormByte::Crypto::Implementation::Encryption::ECDH {
	/**
	 * @brief Generates an ECDH private/public key pair.
	 * @param curveName The name of the elliptic curve (e.g., "secp256r1").
	 * @return ExpectedKeyPair containing the private and public key pair or an error.
	 */
	STORMBYTE_CRYPTO_PRIVATE ExpectedKeyPair GenerateKeyPair(const std::string& curveName) noexcept;

	/**
	 * @brief Derives the shared secret using the private key and the peer's public key.
	 * @param privateKey The private key of the local party.
	 * @param peerPublicKey The public key of the peer.
	 * @return ExpectedCryptoFutureString containing the shared secret or an error.
	 */
	STORMBYTE_CRYPTO_PRIVATE ExpectedCryptoFutureString DeriveSharedSecret(const std::string& privateKey, const std::string& peerPublicKey) noexcept;
}