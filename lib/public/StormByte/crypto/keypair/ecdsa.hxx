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
 * @namespace KeyPair
 * @brief The namespace containing all the keypair-related classes.
 */
namespace StormByte::Crypto::KeyPair {
	/**
	 * @class ECDSA
	 * @brief An ECDSA keypair class.
	 *
	 * The private key, when present, is stored as a @ref StormByte::Crypto::Password
	 * so sensitive material is reference-counted and zeroized when the last owner
	 * is destroyed.
	 */
	class STORMBYTE_CRYPTO_PUBLIC ECDSA final: public Generic {
		public:
			/**
			 * @brief Constructor
			 * @param publicKey The public key material (typically Base64/PEM body).
			 * @param privateKey Optional private key wrapped in @ref Password.
			 */
			inline ECDSA(std::string publicKey, std::optional<Password> privateKey = std::nullopt):
				Generic(Type::ECDSA, std::move(publicKey), std::move(privateKey)) {}

			/**
			 * @brief Copy constructor
			 * @param other The other ECDSA keypair to copy from.
			 */
			ECDSA(const ECDSA& other) = default;

			/**
			 * @brief Move constructor
			 * @param other The other ECDSA keypair to move from.
			 */
			ECDSA(ECDSA&& other) noexcept = default;

			/**
			 * @brief Destructor
			 */
			~ECDSA() noexcept override = default;

			/**
			 * @brief Copy assignment operator
			 * @param other The other ECDSA keypair to copy from.
			 * @return Reference to this ECDSA keypair.
			 */
			ECDSA& operator=(const ECDSA& other) = default;

			/**
			 * @brief Move assignment operator
			 * @param other The other ECDSA keypair to move from.
			 * @return Reference to this ECDSA keypair.
			 */
			ECDSA& operator=(ECDSA&& other) noexcept = default;

			/**
			 * @brief Clone the ECDSA keypair.
			 * @return A pointer to the cloned ECDSA keypair.
			 */
			PointerType Clone() const override {
				return std::make_shared<ECDSA>(*this);
			}

			/**
			 * @brief Move this ECDSA keypair into a new owning pointer.
			 * @return A pointer to the moved ECDSA keypair.
			 */
			PointerType Move() override {
				return std::make_shared<ECDSA>(std::move(*this));
			}

			/**
			 * @brief Generate a new ECDSA keypair.
			 * @param bits The curve size in bits (e.g. 256).
			 * @return A pointer to the generated ECDSA keypair, or nullptr on failure.
			 */
			static PointerType Generate(unsigned short bits) noexcept;
	};
}
