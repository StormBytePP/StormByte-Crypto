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

#include <StormByte/crypto/keypair/generic.hxx>
#include <StormByte/crypto/password.hxx>

#include <optional>
#include <string>

/**
 * @brief Keypairs of the Crypto module.
 */
namespace StormByte::Crypto::KeyPair {
	/**
	 * @class DSA
	 * @brief DSA keypair.
	 */
	class STORMBYTE_CRYPTO_PUBLIC DSA final: public Generic {
		public:
			/**
			 * @name Construction
			 * @{
			 */
			/**
			 * @brief Construct from public material and optional private Password.
			 * @param publicKey Public key.
			 * @param privateKey Optional private key.
			 */
			inline DSA(std::string publicKey, std::optional<Password> privateKey = std::nullopt):
				Generic(Type::DSA, std::move(publicKey), std::move(privateKey)) {}

			/**
			 * @brief Copy constructor.
			 * @param other Keypair to copy.
			 */
			DSA(const DSA& other) = default;

			/**
			 * @brief Move constructor.
			 * @param other Keypair to move.
			 */
			DSA(DSA&& other) noexcept = default;

			/**
			 * @brief Destructor.
			 */
			~DSA() noexcept override = default;

			/**
			 * @brief Copy assignment.
			 * @param other Keypair to copy.
			 * @return Reference to this keypair.
			 */
			DSA& operator=(const DSA& other) = default;

			/**
			 * @brief Move assignment.
			 * @param other Keypair to move.
			 * @return Reference to this keypair.
			 */
			DSA& operator=(DSA&& other) noexcept = default;
			/** @} */

			/**
			 * @brief Clone this keypair.
			 * @return Shared pointer to the clone.
			 */
			PointerType Clone() const override {
				return std::make_shared<DSA>(*this);
			}

			/**
			 * @brief Move this keypair into a new instance.
			 * @return Shared pointer to the moved keypair.
			 */
			PointerType Move() override {
				return std::make_shared<DSA>(std::move(*this));
			}

			/**
			 * @brief Generate a DSA keypair.
			 * @param bits Key size in bits.
			 * @return Keypair pointer, or nullptr.
			 */
			static PointerType Generate(unsigned short bits) noexcept;
	};
}
