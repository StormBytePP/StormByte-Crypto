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

#include <StormByte/crypto/keypair/x25519.hxx>
#include <StormByte/crypto/secret/generic.hxx>

/**
 * @brief Key agreement of the Crypto module.
 */
namespace StormByte::Crypto::Secret {
	/**
	 * @class X25519
	 * @brief X25519 shared-secret derivation.
	 */
	class STORMBYTE_CRYPTO_PUBLIC X25519 final: public Generic {
		public:
			/**
			 * @name Construction
			 * @{
			 */
			/**
			 * @brief Construct from an X25519 keypair (needs private key).
			 * @param keypair Keypair.
			 */
			inline explicit X25519(KeyPair::Generic::PointerType keypair) noexcept
				: Generic(Type::X25519, std::move(keypair)) {}

			/**
			 * @brief Copy constructor.
			 * @param other Object to copy.
			 */
			X25519(const X25519& other) = default;

			/**
			 * @brief Move constructor.
			 * @param other Object to move.
			 */
			X25519(X25519&& other) noexcept = default;

			/**
			 * @brief Destructor.
			 */
			~X25519() noexcept override = default;

			/**
			 * @brief Copy assignment.
			 * @param other Object to copy.
			 * @return Reference to this object.
			 */
			X25519& operator=(const X25519& other) = default;

			/**
			 * @brief Move assignment.
			 * @param other Object to move.
			 * @return Reference to this object.
			 */
			X25519& operator=(X25519&& other) noexcept = default;
			/** @} */

			/**
			 * @brief Clone this object.
			 * @return Shared pointer to the clone.
			 */
			Generic::PointerType Clone() const override {
				return std::make_shared<X25519>(*this);
			}

			/**
			 * @brief Move this object into a new instance.
			 * @return Shared pointer to the moved object.
			 */
			Generic::PointerType Move() override {
				return std::make_shared<X25519>(std::move(*this));
			}

			/**
			 * @brief Derive a shared secret.
			 * @param peerPublicKey Peer public key as Base64.
			 * @return Password on success, or empty.
			 */
			std::optional<Password> Share(const std::string& peerPublicKey) const noexcept override;

			/**
			 * @brief Derive a shared secret without an instance.
			 * @param keypair Local keypair (needs private key).
			 * @param peerPublicKey Peer public key as Base64.
			 * @return Password on success, or empty.
			 */
			static std::optional<Password> DeriveSharedSecret(
				KeyPair::Generic::PointerType keypair,
				const std::string& peerPublicKey) noexcept;
	};
}
