/*
 * Copyright (C) 2024-2026 David C. Manuelda (StormBytePP)
 *
 * This file is part of StormByte.
 *
 * StormByte is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * StormByte is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with StormByte. If not, see <https://www.gnu.org/licenses/>.
 */

#pragma once

#include <StormByte/crypto/keypair/x25519.hxx>
#include <StormByte/crypto/secret/generic.hxx>

/**
 * @namespace Secret
 * @brief The namespace containing key-agreement (shared secret) classes.
 */
namespace StormByte::Crypto::Secret {

	/**
	 * @class X25519
	 * @brief X25519 Diffie-Hellman shared secret derivation.
	 *
	 * The local private key is binary material inside @ref Password;
	 * the peer public key is Base64-encoded.
	 */
	class STORMBYTE_CRYPTO_PUBLIC X25519 final: public Generic {
		public:
			/**
			 * @brief Construct from an X25519 keypair.
			 * @param keypair Keypair that must contain a private key.
			 */
			inline explicit X25519(KeyPair::Generic::PointerType keypair) noexcept
				: Generic(Type::X25519, std::move(keypair)) {}

			/**
			 * @brief Copy constructor.
			 * @param other The other X25519 instance to copy from.
			 */
			X25519(const X25519& other) = default;

			/**
			 * @brief Move constructor.
			 * @param other The other X25519 instance to move from.
			 */
			X25519(X25519&& other) noexcept = default;

			/**
			 * @brief Destructor.
			 */
			~X25519() noexcept override = default;

			/**
			 * @brief Copy assignment operator.
			 * @param other The other X25519 instance to copy from.
			 * @return Reference to this instance.
			 */
			X25519& operator=(const X25519& other) = default;

			/**
			 * @brief Move assignment operator.
			 * @param other The other X25519 instance to move from.
			 * @return Reference to this instance.
			 */
			X25519& operator=(X25519&& other) noexcept = default;

			/**
			 * @brief Clone this instance.
			 * @return A shared pointer to a copy of this object.
			 */
			Generic::PointerType Clone() const override {
				return std::make_shared<X25519>(*this);
			}

			/**
			 * @brief Move this instance into a new shared pointer.
			 * @return A shared pointer owning the moved object.
			 */
			Generic::PointerType Move() override {
				return std::make_shared<X25519>(std::move(*this));
			}

			/**
			 * @brief Derive the shared secret with a peer public key.
			 * @param peerPublicKey Peer public key encoded as Base64.
			 * @return Shared secret as @ref Password, or nullopt on failure.
			 */
			std::optional<Password> Share(const std::string& peerPublicKey) const noexcept override;

			/**
			 * @brief Static helper to derive a shared secret without an instance.
			 * @param keypair Local keypair (must include private key).
			 * @param peerPublicKey Peer public key encoded as Base64.
			 * @return Shared secret as @ref Password, or nullopt on failure.
			 */
			static std::optional<Password> DeriveSharedSecret(
				KeyPair::Generic::PointerType keypair,
				const std::string& peerPublicKey) noexcept;
	};
}
