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

#include <StormByte/crypto/keypair/ed25519.hxx>
#include <StormByte/crypto/signer/generic.hxx>

/**
 * @brief Signers of the Crypto module.
 */
namespace StormByte::Crypto::Signer {
	/**
	 * @class ED25519
	 * @brief Ed25519 signer.
	 */
	class STORMBYTE_CRYPTO_PUBLIC ED25519 final: public Generic {
		public:
			/**
			 * @name Construction
			 * @{
			 */
			/**
			 * @brief Construct from a keypair pointer.
			 * @param keypair Keypair.
			 */
			inline ED25519(KeyPair::Generic::PointerType keypair):
				Generic(Type::ED25519, keypair) {}

			/**
			 * @brief Construct by cloning an Ed25519 keypair.
			 * @param keypair Keypair.
			 */
			inline ED25519(const KeyPair::ED25519& keypair):
				Generic(Type::ED25519, keypair) {}

			/**
			 * @brief Construct by moving an Ed25519 keypair.
			 * @param keypair Keypair.
			 */
			inline ED25519(KeyPair::ED25519&& keypair):
				Generic(Type::ED25519, keypair) {}

			/**
			 * @brief Copy constructor.
			 * @param other Signer to copy.
			 */
			ED25519(const ED25519& other) = default;

			/**
			 * @brief Move constructor.
			 * @param other Signer to move.
			 */
			ED25519(ED25519&& other) noexcept = default;

			/**
			 * @brief Destructor.
			 */
			~ED25519() noexcept = default;

			/**
			 * @brief Copy assignment.
			 * @param other Signer to copy.
			 * @return Reference to this signer.
			 */
			ED25519& operator=(const ED25519& other) = default;

			/**
			 * @brief Move assignment.
			 * @param other Signer to move.
			 * @return Reference to this signer.
			 */
			ED25519& operator=(ED25519&& other) noexcept = default;
			/** @} */

			/**
			 * @brief Clone this signer.
			 * @return Shared pointer to the clone.
			 */
			PointerType Clone() const noexcept override {
				return std::make_shared<ED25519>(*this);
			}

			/**
			 * @brief Move this signer into a new instance.
			 * @return Shared pointer to the moved signer.
			 */
			PointerType Move() noexcept override {
				return std::make_shared<ED25519>(std::move(*this));
			}

		private:
			/**
			 * @brief Sign a byte span.
			 * @param input Input bytes.
			 * @param output Destination buffer.
			 * @return true on success.
			 */
			bool DoSign(std::span<const std::byte> input, Buffer::WriteOnly& output) const noexcept override;

			/**
			 * @brief Sign a Consumer.
			 * @param consumer Input consumer.
			 * @param mode Copy or move.
			 * @return Consumer with the signature.
			 */
			Buffer::Consumer DoSign(Buffer::Consumer consumer, ReadMode mode) const noexcept override;

			/**
			 * @brief Verify a byte span.
			 * @param input Input bytes.
			 * @param signature Signature.
			 * @return true if valid.
			 */
			bool DoVerify(std::span<const std::byte> input, const std::string& signature) const noexcept override;

			/**
			 * @brief Verify a Consumer.
			 * @param consumer Input consumer.
			 * @param signature Signature.
			 * @param mode Copy or move.
			 * @return true if valid.
			 */
			bool DoVerify(Buffer::Consumer consumer, const std::string& signature, ReadMode mode) const noexcept override;
	};
}
