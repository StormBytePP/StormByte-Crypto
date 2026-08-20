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

#include <StormByte/crypto/keypair/generic.hxx>
#include <StormByte/crypto/password.hxx>

#include <optional>
#include <string>

/**
 * @namespace KeyPair
 * @brief The namespace containing all the keypair-related classes.
 */
namespace StormByte::Crypto::KeyPair {
	/**
	 * @class ECC
	 * @brief An Elliptic Curve Cryptography keypair class.
	 *
	 * The private key, when present, is stored as a @ref StormByte::Crypto::Password
	 * so sensitive material is reference-counted and zeroized when the last owner
	 * is destroyed.
	 */
	class STORMBYTE_CRYPTO_PUBLIC ECC final: public Generic {
		public:
			/**
			 * @brief Constructor
			 * @param publicKey The public key material (typically Base64/PEM body).
			 * @param privateKey Optional private key wrapped in @ref Password.
			 */
			inline ECC(std::string publicKey, std::optional<Password> privateKey = std::nullopt):
				Generic(Type::ECC, std::move(publicKey), std::move(privateKey)) {}

			/**
			 * @brief Copy constructor
			 * @param other The other ECC keypair to copy from.
			 */
			ECC(const ECC& other) = default;

			/**
			 * @brief Move constructor
			 * @param other The other ECC keypair to move from.
			 */
			ECC(ECC&& other) noexcept = default;

			/**
			 * @brief Destructor
			 */
			~ECC() noexcept override = default;

			/**
			 * @brief Copy assignment operator
			 * @param other The other ECC keypair to copy from.
			 * @return Reference to this ECC keypair.
			 */
			ECC& operator=(const ECC& other) = default;

			/**
			 * @brief Move assignment operator
			 * @param other The other ECC keypair to move from.
			 * @return Reference to this ECC keypair.
			 */
			ECC& operator=(ECC&& other) noexcept = default;

			/**
			 * @brief Clone the ECC keypair.
			 * @return A pointer to the cloned ECC keypair.
			 */
			PointerType Clone() const override {
				return std::make_shared<ECC>(*this);
			}

			/**
			 * @brief Move this ECC keypair into a new owning pointer.
			 * @return A pointer to the moved ECC keypair.
			 */
			PointerType Move() override {
				return std::make_shared<ECC>(std::move(*this));
			}

			/**
			 * @brief Generate a new ECC keypair.
			 * @param bits The curve size in bits (e.g. 256).
			 * @return A pointer to the generated ECC keypair, or nullptr on failure.
			 */
			static PointerType Generate(unsigned short bits) noexcept;
	};
}
