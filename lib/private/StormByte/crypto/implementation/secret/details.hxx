#pragma once

#include <StormByte/crypto/password.hxx>
#include <StormByte/crypto/visibility.h>

#include <optional>
#include <string>

namespace StormByte::Crypto::Implementation::Secret {
	/**
	 * @brief ECDH shared-secret derivation (raw domain path + ASN.1 fallback).
	 * @param privateKey Local private key material.
	 * @param peerPublicKeyBase64 Peer public key (Base64).
	 * @param bits Curve size in bits (256 / 384 / 521).
	 * @return Shared secret as Password, or nullopt on failure.
	 */
	std::optional<Password> ECDHShare(const Password& privateKey,
									const std::string& peerPublicKeyBase64,
									unsigned short bits) noexcept;

	/**
	 * @brief X25519 shared-secret derivation.
	 * @param privateKey Local private key material.
	 * @param peerPublicKeyBase64 Peer public key (Base64).
	 * @return Shared secret as Password, or nullopt on failure.
	 */
	std::optional<Password> X25519Share(const Password& privateKey,
										const std::string& peerPublicKeyBase64) noexcept;
}
