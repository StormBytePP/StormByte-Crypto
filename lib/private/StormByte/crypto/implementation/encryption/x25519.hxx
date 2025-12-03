#pragma once

#include <StormByte/crypto/implementation/encryption/typedefs.hxx>

/**
 * @namespace X25519
 * @brief The namespace containing X25519 key exchange functions.
 */
namespace StormByte::Crypto::Implementation::Encryption::X25519 {
	/**
	 * @brief Generates an X25519 private/public key pair.
	 * @return ExpectedKeyPair containing the private and public key pair or an error.
	 */
	STORMBYTE_CRYPTO_PRIVATE ExpectedKeyPair GenerateKeyPair() noexcept;

	/**
	 * @brief Derives the shared secret using the private key and the peer's public key.
	 * @param privateKey The private key of the local party.
	 * @param peerPublicKey The public key of the peer.
	 * @return ExpectedCryptoString containing the shared secret or an error.
	 */
	STORMBYTE_CRYPTO_PRIVATE ExpectedCryptoString DeriveSharedSecret(const std::string& privateKey, const std::string& peerPublicKey) noexcept;
}
