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

#include <StormByte/crypto/keypair/ecdh.hxx>
#include <StormByte/crypto/secret/generic.hxx>

/**
 * @brief Key agreement of the Crypto module.
 */
namespace StormByte::Crypto::Secret {
	/**
	 * @class ECDH
	 * @brief ECDH shared-secret derivation.
	 */
	class STORMBYTE_CRYPTO_PUBLIC ECDH final: public Generic {
		public:
			/**
			 * @name Construction
			 * @{
			 */
			/**
			 * @brief Construct from a keypair pointer.
			 * @param keypair Must be @ref KeyPair::Type::ECDH.
			 * @param bits Curve size in bits. Must match the keypair.
			 */
			inline ECDH(KeyPair::Generic::PointerType keypair, unsigned short bits = 256) noexcept:
				Generic(Type::ECDH, keypair), m_bits(bits) {}

			/**
			 * @brief Construct by cloning an ECDH keypair.
			 * @param keypair Keypair.
			 * @param bits Curve size in bits.
			 */
			inline ECDH(const KeyPair::ECDH& keypair, unsigned short bits = 256) noexcept:
				Generic(Type::ECDH, keypair.Clone()), m_bits(bits) {}

			/**
			 * @brief Construct by moving an ECDH keypair.
			 * @param keypair Keypair.
			 * @param bits Curve size in bits.
			 */
			inline ECDH(KeyPair::ECDH&& keypair, unsigned short bits = 256) noexcept:
				Generic(Type::ECDH, keypair.Move()), m_bits(bits) {}

			/**
			 * @brief Copy constructor.
			 * @param other Object to copy.
			 */
			ECDH(const ECDH& other) = default;

			/**
			 * @brief Move constructor.
			 * @param other Object to move.
			 */
			ECDH(ECDH&& other) noexcept = default;

			/**
			 * @brief Destructor.
			 */
			~ECDH() noexcept override = default;

			/**
			 * @brief Copy assignment.
			 * @param other Object to copy.
			 * @return Reference to this object.
			 */
			ECDH& operator=(const ECDH& other) = default;

			/**
			 * @brief Move assignment.
			 * @param other Object to move.
			 * @return Reference to this object.
			 */
			ECDH& operator=(ECDH&& other) noexcept = default;
			/** @} */

			/**
			 * @brief Clone this object.
			 * @return Shared pointer to the clone.
			 */
			PointerType Clone() const noexcept override {
				return std::make_shared<ECDH>(*this);
			}

			/**
			 * @brief Move this object into a new instance.
			 * @return Shared pointer to the moved object.
			 */
			PointerType Move() noexcept override {
				return std::make_shared<ECDH>(std::move(*this));
			}

			/**
			 * @brief Derive a shared secret.
			 * @param peerPublicKey Peer public key.
			 * @return Password on success, or empty.
			 */
			std::optional<Password> Share(const std::string& peerPublicKey) const noexcept override;

		private:
			unsigned short m_bits;	///< Curve size in bits
	};
}
