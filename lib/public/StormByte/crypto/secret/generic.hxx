/*
 * Copyright (C) 2024-2026 David C. Manuelda (StormBytePP)
 *
 * This file is part of StormByte-Crypto.
 *
 * StormByte-Crypto is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 3
 * or later, as published by the Free Software Foundation.
 *
 * StormByte-Crypto is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with StormByte-Crypto. If not, see
 * <https://www.gnu.org/licenses/lgpl-3.0.html>.
 */

#pragma once

#include <StormByte/clonable.hxx>
#include <StormByte/crypto/keypair/generic.hxx>
#include <StormByte/crypto/password.hxx>
#include <StormByte/crypto/visibility.h>

#include <optional>
#include <string>

/**
 * @namespace Secret
 * @brief The namespace containing key-agreement (shared secret) classes.
 */
namespace StormByte::Crypto::Secret {

	/**
	 * @enum Type
	 * @brief The types of key-agreement algorithms available.
	 */
	enum class Type {
		ECDH,		///< Elliptic Curve Diffie-Hellman
		X25519,		///< X25519 Diffie-Hellman
	};

	/**
	 * @class Generic
	 * @brief Base class for key-agreement objects.
	 *
	 * Holds a local keypair and exposes a uniform interface to derive a
	 * shared secret from a peer public key. Concrete types implement
	 * the algorithm-specific logic (ECDH, X25519, etc.).
	 */
	class STORMBYTE_CRYPTO_PUBLIC Generic: public StormByte::Clonable<Generic> {
		public:
			/**
			 * @brief Copy constructor.
			 * @param other The other Generic instance to copy from.
			 */
			Generic(const Generic& other) = default;

			/**
			 * @brief Move constructor.
			 * @param other The other Generic instance to move from.
			 */
			Generic(Generic&& other) noexcept = default;

			/**
			 * @brief Virtual destructor.
			 */
			virtual ~Generic() noexcept = default;

			/**
			 * @brief Copy assignment operator.
			 * @param other The other Generic instance to copy from.
			 * @return Reference to this instance.
			 */
			Generic& operator=(const Generic& other) = default;

			/**
			 * @brief Move assignment operator.
			 * @param other The other Generic instance to move from.
			 * @return Reference to this instance.
			 */
			Generic& operator=(Generic&& other) noexcept = default;

			/**
			 * @brief Gets the algorithm type of this instance.
			 * @return The key-agreement type.
			 */
			inline Type Type() const noexcept {
				return m_type;
			}

			/**
			 * @brief Derive a shared secret with a peer public key.
			 * @param peerPublicKey Peer public key encoded as Base64.
			 * @return Shared secret as @ref Password on success, or nullopt on failure.
			 */
			virtual std::optional<Password> Share(const std::string& peerPublicKey) const noexcept = 0;

		protected:
			enum Type m_type;							///< Algorithm type
			KeyPair::Generic::PointerType m_keypair;	///< Local keypair (must include private key)

			/**
			 * @brief Constructor.
			 * @param type Algorithm type.
			 * @param keypair Local keypair used for agreement.
			 */
			inline Generic(enum Type type, KeyPair::Generic::PointerType keypair) noexcept
				: m_type(type), m_keypair(std::move(keypair)) {}
	};

	/**
	 * @brief Creates a key-agreement object of the specified type.
	 * @param type The algorithm type to create.
	 * @param keypair The matching keypair for that algorithm.
	 * @return A pointer to the created object, or nullptr on failure
	 *         (null keypair or type/keypair mismatch).
	 *
	 * @note For ECDH the curve size defaults to 256 bits. When using
	 *       secp384r1 or secp521r1, construct @ref ECDH with the explicit bit size.
	 */
	STORMBYTE_CRYPTO_PUBLIC Generic::PointerType Create(Type type, KeyPair::Generic::PointerType keypair) noexcept;
}
