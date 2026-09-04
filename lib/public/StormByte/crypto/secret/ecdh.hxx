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
 * @namespace Secret
 * @brief The namespace containing all the secret-related classes.
 */
namespace StormByte::Crypto::Secret {
	/**
	 * @class ECDH
	 * @brief Elliptic Curve Diffie-Hellman shared-secret derivation.
	 *
	 * Uses a @ref KeyPair::ECDH keypair to derive a shared secret with a peer
	 * public key. Including this header also provides @ref KeyPair::ECDH so
	 * callers can generate matching keypairs without an extra include.
	 */
	class STORMBYTE_CRYPTO_PUBLIC ECDH final: public Generic {
		public:
			/**
			 * @brief Constructor
			 * @param keypair The ECDH keypair (must be @ref KeyPair::Type::ECDH).
			 * @param bits Curve size in bits (default 256). Must match the keypair curve.
			 */
			inline ECDH(KeyPair::Generic::PointerType keypair, unsigned short bits = 256) noexcept:
				Generic(Type::ECDH, keypair), m_bits(bits) {}

			/**
			 * @brief Constructor
			 * @param keypair The ECDH keypair.
			 * @param bits Curve size in bits (default 256).
			 */
			inline ECDH(const KeyPair::ECDH& keypair, unsigned short bits = 256) noexcept:
				Generic(Type::ECDH, keypair.Clone()), m_bits(bits) {}

			/**
			 * @brief Constructor
			 * @param keypair The ECDH keypair.
			 * @param bits Curve size in bits (default 256).
			 */
			inline ECDH(KeyPair::ECDH&& keypair, unsigned short bits = 256) noexcept:
				Generic(Type::ECDH, keypair.Move()), m_bits(bits) {}

			/**
			 * @brief Copy constructor
			 * @param other The other ECDH instance to copy from.
			 */
			ECDH(const ECDH& other) = default;

			/**
			 * @brief Move constructor
			 * @param other The other ECDH instance to move from.
			 */
			ECDH(ECDH&& other) noexcept = default;

			/**
			 * @brief Destructor
			 */
			~ECDH() noexcept override = default;

			/**
			 * @brief Copy assignment operator
			 * @param other The other ECDH instance to copy from.
			 * @return Reference to this ECDH instance.
			 */
			ECDH& operator=(const ECDH& other) = default;

			/**
			 * @brief Move assignment operator
			 * @param other The other ECDH instance to move from.
			 * @return Reference to this ECDH instance.
			 */
			ECDH& operator=(ECDH&& other) noexcept = default;

			/**
			 * @brief Clone this ECDH instance.
			 * @return A pointer to the cloned instance.
			 */
			PointerType Clone() const noexcept override {
				return std::make_shared<ECDH>(*this);
			}

			/**
			 * @brief Move this ECDH instance.
			 * @return A pointer to the moved instance.
			 */
			PointerType Move() noexcept override {
				return std::make_shared<ECDH>(std::move(*this));
			}

			/**
			 * @brief Derive a shared secret with a peer public key.
			 * @param peerPublicKey Peer public key (Base64 / library format).
			 * @return The shared secret as @ref Password on success, or std::nullopt on failure.
			 */
			std::optional<Password> Share(const std::string& peerPublicKey) const noexcept override;

		private:
			unsigned short m_bits;	///< Curve size in bits used for agreement
	};
}
