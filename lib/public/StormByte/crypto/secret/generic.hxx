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
 * @brief Key agreement of the Crypto module.
 */
namespace StormByte::Crypto::Secret {
	/**
	 * @enum Type
	 * @brief Available agreement algorithms.
	 */
	enum class Type {
		ECDH,		///< ECDH
		X25519,		///< X25519
	};

	/**
	 * @class Generic
	 * @brief Abstract key-agreement object.
	 *
	 * Holds a local keypair and derives a shared secret from a peer public key.
	 */
	class STORMBYTE_CRYPTO_PUBLIC Generic: public StormByte::Clonable<Generic> {
		public:
			/**
			 * @name Construction
			 * @{
			 */
			/**
			 * @brief Copy constructor.
			 * @param other Object to copy.
			 */
			Generic(const Generic& other) = default;

			/**
			 * @brief Move constructor.
			 * @param other Object to move.
			 */
			Generic(Generic&& other) noexcept = default;

			/**
			 * @brief Destructor.
			 */
			virtual ~Generic() noexcept = default;

			/**
			 * @brief Copy assignment.
			 * @param other Object to copy.
			 * @return Reference to this object.
			 */
			Generic& operator=(const Generic& other) = default;

			/**
			 * @brief Move assignment.
			 * @param other Object to move.
			 * @return Reference to this object.
			 */
			Generic& operator=(Generic&& other) noexcept = default;
			/** @} */

			/**
			 * @brief Algorithm of this instance.
			 * @return Agreement type.
			 */
			inline Type Type() const noexcept {
				return m_type;
			}

			/**
			 * @brief Derive a shared secret.
			 * @param peerPublicKey Peer public key as Base64.
			 * @return Password on success, or empty.
			 */
			virtual std::optional<Password> Share(const std::string& peerPublicKey) const noexcept = 0;

		protected:
			enum Type m_type;							///< Algorithm
			KeyPair::Generic::PointerType m_keypair;	///< Local keypair (needs private key)

			/**
			 * @brief Construct with algorithm and keypair.
			 * @param type Algorithm.
			 * @param keypair Local keypair.
			 */
			inline Generic(enum Type type, KeyPair::Generic::PointerType keypair) noexcept
				: m_type(type), m_keypair(std::move(keypair)) {}
	};

	/**
	 * @brief Create an agreement object.
	 * @param type Algorithm.
	 * @param keypair Matching keypair.
	 * @return Object pointer, or nullptr if the pair is null or mismatched.
	 * @note ECDH defaults to 256 bits. For secp384r1/secp521r1 construct @ref ECDH with the bit size.
	 */
	STORMBYTE_CRYPTO_PUBLIC Generic::PointerType Create(Type type, KeyPair::Generic::PointerType keypair) noexcept;
}
