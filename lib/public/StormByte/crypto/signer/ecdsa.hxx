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

#include <StormByte/crypto/keypair/ecdsa.hxx>
#include <StormByte/crypto/signer/generic.hxx>

/**
 * @brief Signers of the Crypto module.
 */
namespace StormByte::Crypto::Signer {
	/**
	 * @class ECDSA
	 * @brief ECDSA signer (ECP with SHA-256).
	 */
	class STORMBYTE_CRYPTO_PUBLIC ECDSA final: public Generic {
		public:
			/**
			 * @name Construction
			 * @{
			 */
			/**
			 * @brief Construct from a keypair pointer.
			 * @param keypair Keypair.
			 */
			inline ECDSA(KeyPair::Generic::PointerType keypair):
				Generic(Type::ECDSA, keypair) {}

			/**
			 * @brief Construct by cloning an ECDSA keypair.
			 * @param keypair Keypair.
			 */
			inline ECDSA(const KeyPair::ECDSA& keypair):
				Generic(Type::ECDSA, keypair) {}

			/**
			 * @brief Construct by moving an ECDSA keypair.
			 * @param keypair Keypair.
			 */
			inline ECDSA(KeyPair::ECDSA&& keypair):
				Generic(Type::ECDSA, keypair) {}

			/**
			 * @brief Copy constructor.
			 * @param other Signer to copy.
			 */
			ECDSA(const ECDSA& other) = default;

			/**
			 * @brief Move constructor.
			 * @param other Signer to move.
			 */
			ECDSA(ECDSA&& other) noexcept = default;

			/**
			 * @brief Destructor.
			 */
			~ECDSA() noexcept = default;

			/**
			 * @brief Copy assignment.
			 * @param other Signer to copy.
			 * @return Reference to this signer.
			 */
			ECDSA& operator=(const ECDSA& other) = default;

			/**
			 * @brief Move assignment.
			 * @param other Signer to move.
			 * @return Reference to this signer.
			 */
			ECDSA& operator=(ECDSA&& other) noexcept = default;
			/** @} */

			/**
			 * @brief Clone this signer.
			 * @return Shared pointer to the clone.
			 */
			PointerType Clone() const noexcept override {
				return std::make_shared<ECDSA>(*this);
			}

			/**
			 * @brief Move this signer into a new instance.
			 * @return Shared pointer to the moved signer.
			 */
			PointerType Move() noexcept override {
				return std::make_shared<ECDSA>(std::move(*this));
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
