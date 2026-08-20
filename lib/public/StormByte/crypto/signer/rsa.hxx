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

#include <StormByte/crypto/signer/generic.hxx>
#include <StormByte/crypto/keypair/rsa.hxx>

/**
 * @namespace Signer
 * @brief The namespace containing all the signer-related classes.
 */
namespace StormByte::Crypto::Signer {
	/**
	 * @class RSA
	 * @brief RSA digital signature class (PKCS#1 v1.5 with SHA-256).
	 */
	class STORMBYTE_CRYPTO_PUBLIC RSA final: public Generic {
		public:
			/**
			 * @brief Constructor
			 * @param keypair The keypair used for signing and verification.
			 */
			inline RSA(KeyPair::Generic::PointerType keypair):
				Generic(Type::RSA, keypair) {}

			/**
			 * @brief Constructor
			 * @param keypair The keypair used for signing and verification.
			 */
			inline RSA(const KeyPair::RSA& keypair):
				Generic(Type::RSA, keypair) {}

			/**
			 * @brief Constructor
			 * @param keypair The keypair used for signing and verification.
			 */
			inline RSA(KeyPair::RSA&& keypair):
				Generic(Type::RSA, keypair) {}

			/**
			 * @brief Copy constructor
			 * @param other The other RSA signer to copy from.
			 */
			RSA(const RSA& other) = default;

			/**
			 * @brief Move constructor
			 * @param other The other RSA signer to move from.
			 */
			RSA(RSA&& other) noexcept = default;

			/**
			 * @brief Destructor
			 */
			~RSA() noexcept = default;

			/**
			 * @brief Copy assignment operator
			 * @param other The other RSA signer to copy from.
			 * @return Reference to this RSA signer.
			 */
			RSA& operator=(const RSA& other) = default;

			/**
			 * @brief Move assignment operator
			 * @param other The other RSA signer to move from.
			 * @return Reference to this RSA signer.
			 */
			RSA& operator=(RSA&& other) noexcept = default;

			/**
			 * @brief Clone the RSA signer.
			 * @return A pointer to the cloned RSA signer.
			 */
			PointerType Clone() const noexcept override {
				return std::make_shared<RSA>(*this);
			}

			/**
			 * @brief Move the RSA signer.
			 * @return A pointer to the moved RSA signer.
			 */
			PointerType Move() noexcept override {
				return std::make_shared<RSA>(std::move(*this));
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
