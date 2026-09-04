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
	 * @class ECDH
	 * @brief ECDH keypair.
	 */
	class STORMBYTE_CRYPTO_PUBLIC ECDH final: public Generic {
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
			inline ECDH(std::string publicKey, std::optional<Password> privateKey = std::nullopt):
				Generic(Type::ECDH, std::move(publicKey), std::move(privateKey)) {}

			/**
			 * @brief Copy constructor.
			 * @param other Keypair to copy.
			 */
			ECDH(const ECDH& other) = default;

			/**
			 * @brief Move constructor.
			 * @param other Keypair to move.
			 */
			ECDH(ECDH&& other) noexcept = default;

			/**
			 * @brief Destructor.
			 */
			~ECDH() noexcept override = default;

			/**
			 * @brief Copy assignment.
			 * @param other Keypair to copy.
			 * @return Reference to this keypair.
			 */
			ECDH& operator=(const ECDH& other) = default;

			/**
			 * @brief Move assignment.
			 * @param other Keypair to move.
			 * @return Reference to this keypair.
			 */
			ECDH& operator=(ECDH&& other) noexcept = default;
			/** @} */

			/**
			 * @brief Clone this keypair.
			 * @return Shared pointer to the clone.
			 */
			PointerType Clone() const override {
				return std::make_shared<ECDH>(*this);
			}

			/**
			 * @brief Move this keypair into a new instance.
			 * @return Shared pointer to the moved keypair.
			 */
			PointerType Move() override {
				return std::make_shared<ECDH>(std::move(*this));
			}

			/**
			 * @brief Generate an ECDH keypair.
			 * @param bits Curve size in bits (e.g. 256).
			 * @return Keypair pointer, or nullptr.
			 */
			static PointerType Generate(unsigned short bits) noexcept;
	};
}
