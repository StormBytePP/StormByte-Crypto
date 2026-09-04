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

#include <StormByte/crypto/signer/generic.hxx>
#include <StormByte/crypto/keypair/ed25519.hxx>

/**
 * @namespace Signer
 * @brief The namespace containing all the signer-related classes.
 */
namespace StormByte::Crypto::Signer {
	/**
	 * @class ED25519
	 * @brief Ed25519 digital signature class.
	 */
	class STORMBYTE_CRYPTO_PUBLIC ED25519 final: public Generic {
		public:
			/**
			 * @brief Constructor
			 * @param keypair The keypair used for signing and verification.
			 */
			inline ED25519(KeyPair::Generic::PointerType keypair):
				Generic(Type::ED25519, keypair) {}

			/**
			 * @brief Constructor
			 * @param keypair The keypair used for signing and verification.
			 */
			inline ED25519(const KeyPair::ED25519& keypair):
				Generic(Type::ED25519, keypair) {}

			/**
			 * @brief Constructor
			 * @param keypair The keypair used for signing and verification.
			 */
			inline ED25519(KeyPair::ED25519&& keypair):
				Generic(Type::ED25519, keypair) {}

			/**
			 * @brief Copy constructor
			 * @param other The other ED25519 signer to copy from.
			 */
			ED25519(const ED25519& other) = default;

			/**
			 * @brief Move constructor
			 * @param other The other ED25519 signer to move from.
			 */
			ED25519(ED25519&& other) noexcept = default;

			/**
			 * @brief Destructor
			 */
			~ED25519() noexcept = default;

			/**
			 * @brief Copy assignment operator
			 * @param other The other ED25519 signer to copy from.
			 * @return Reference to this ED25519 signer.
			 */
			ED25519& operator=(const ED25519& other) = default;

			/**
			 * @brief Move assignment operator
			 * @param other The other ED25519 signer to move from.
			 * @return Reference to this ED25519 signer.
			 */
			ED25519& operator=(ED25519&& other) noexcept = default;

			/**
			 * @brief Clone the ED25519 signer.
			 * @return A pointer to the cloned ED25519 signer.
			 */
			PointerType Clone() const noexcept override {
				return std::make_shared<ED25519>(*this);
			}

			/**
			 * @brief Move the ED25519 signer.
			 * @return A pointer to the moved ED25519 signer.
			 */
			PointerType Move() noexcept override {
				return std::make_shared<ED25519>(std::move(*this));
			}

		private:
			/**
			 * @brief Implementation of the signing logic.
			 * @param input The input buffer to sign.
			 * @param output The output buffer to write the signature to.
			 * @return true if signing was successful, false otherwise.
			 */
			bool DoSign(std::span<const std::byte> input, Buffer::WriteOnly& output) const noexcept override;

			/**
			 * @brief Implementation of the signing logic for Consumer buffers.
			 * @param consumer The Consumer buffer to sign.
			 * @param mode The read mode indicating copy or move.
			 * @return A Consumer buffer containing the signature.
			 */
			Buffer::Consumer DoSign(Buffer::Consumer consumer, ReadMode mode) const noexcept override;

			/**
			 * @brief Implementation of the verification logic.
			 * @param input The input buffer to verify.
			 * @param signature The signature to verify against.
			 * @return true if verification was successful, false otherwise.
			 */
			bool DoVerify(std::span<const std::byte> input, const std::string& signature) const noexcept override;

			/**
			 * @brief Implementation of the verification logic for Consumer buffers.
			 * @param consumer The Consumer buffer to verify.
			 * @param signature The signature to verify against.
			 * @param mode The read mode indicating copy or move.
			 * @return true if verification was successful, false otherwise.
			 */
			bool DoVerify(Buffer::Consumer consumer, const std::string& signature, ReadMode mode) const noexcept override;
	};
}
