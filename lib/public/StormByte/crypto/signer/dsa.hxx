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
#include <StormByte/crypto/keypair/dsa.hxx>

/**
 * @namespace Signer
 * @brief The namespace containing all the signer-related classes.
 */
namespace StormByte::Crypto::Signer {
	/**
	 * @class DSA
	 * @brief DSA digital signature class.
	 */
	class STORMBYTE_CRYPTO_PUBLIC DSA final: public Generic {
		public:
			/**
			 * @brief Constructor
			 * @param keypair The keypair used for signing and verification.
			 */
			inline DSA(KeyPair::Generic::PointerType keypair):
				Generic(Type::DSA, keypair) {}

			/**
			 * @brief Constructor
			 * @param keypair The keypair used for signing and verification.
			 */
			inline DSA(const KeyPair::DSA& keypair):
				Generic(Type::DSA, keypair) {}

			/**
			 * @brief Constructor
			 * @param keypair The keypair used for signing and verification.
			 */
			inline DSA(KeyPair::DSA&& keypair):
				Generic(Type::DSA, keypair) {}

			/**
			 * @brief Copy constructor
			 * @param other The other DSA signer to copy from.
			 */
			DSA(const DSA& other) = default;

			/**
			 * @brief Move constructor
			 * @param other The other DSA signer to move from.
			 */
			DSA(DSA&& other) noexcept = default;

			/**
			 * @brief Destructor
			 */
			~DSA() noexcept = default;

			/**
			 * @brief Copy assignment operator
			 * @param other The other DSA signer to copy from.
			 * @return Reference to this DSA signer.
			 */
			DSA& operator=(const DSA& other) = default;

			/**
			 * @brief Move assignment operator
			 * @param other The other DSA signer to move from.
			 * @return Reference to this DSA signer.
			 */
			DSA& operator=(DSA&& other) noexcept = default;

			/**
			 * @brief Clone the DSA signer.
			 * @return A pointer to the cloned DSA signer.
			 */
			PointerType Clone() const noexcept override {
				return std::make_shared<DSA>(*this);
			}

			/**
			 * @brief Move the DSA signer.
			 * @return A pointer to the moved DSA signer.
			 */
			PointerType Move() noexcept override {
				return std::make_shared<DSA>(std::move(*this));
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
