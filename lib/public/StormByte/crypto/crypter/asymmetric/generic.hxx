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

#include <StormByte/crypto/crypter/generic.hxx>
#include <StormByte/crypto/keypair/generic.hxx>

/**
 * @brief Ciphers of the Crypto module.
 */
namespace StormByte::Crypto::Crypter {
	/**
	 * @class Asymmetric
	 * @brief Keypair-based asymmetric crypter.
	 */
	class STORMBYTE_CRYPTO_PUBLIC Asymmetric: public Generic {
		public:
			/**
			 * @enum Strategy
			 * @brief How payload bytes are sealed.
			 */
			enum class Strategy {
				Hybrid,	///< Encapsulate a random AES-GCM key with the public key
				Native,	///< Pure asymmetric encryption
			};

			/**
			 * @name Construction
			 * @{
			 */
			/**
			 * @brief Copy constructor.
			 * @param other Crypter to copy.
			 */
			Asymmetric(const Asymmetric& other) = default;

			/**
			 * @brief Move constructor.
			 * @param other Crypter to move.
			 */
			Asymmetric(Asymmetric&& other) noexcept = default;

			/**
			 * @brief Destructor.
			 */
			virtual ~Asymmetric() noexcept = default;

			/**
			 * @brief Copy assignment.
			 * @param other Crypter to copy.
			 * @return Reference to this crypter.
			 */
			Asymmetric& operator=(const Asymmetric& other) = default;

			/**
			 * @brief Move assignment.
			 * @param other Crypter to move.
			 * @return Reference to this crypter.
			 */
			Asymmetric& operator=(Asymmetric&& other) noexcept = default;
			/** @} */

			/**
			 * @brief Keypair used by this crypter.
			 * @return Shared keypair.
			 */
			KeyPair::Generic::PointerType KeyPair() const noexcept {
				return m_keypair;
			}

			/**
			 * @name Encrypt
			 * @{
			 */
			/**
			 * @brief Encrypt a byte span.
			 * @param input Input bytes.
			 * @param output Destination buffer.
			 * @param strategy Native or Hybrid. Default Native.
			 * @return true on success.
			 */
			bool Encrypt(std::span<const std::byte> input, Buffer::WriteOnly& output, Strategy strategy = Strategy::Native) const noexcept;

			/**
			 * @brief Encrypt a read-only buffer (copy).
			 * @param input Input buffer.
			 * @param output Destination buffer.
			 * @param strategy Native or Hybrid. Default Native.
			 * @return true on success.
			 */
			bool Encrypt(const Buffer::ReadOnly& input, Buffer::WriteOnly& output, Strategy strategy = Strategy::Native) const noexcept;

			/**
			 * @brief Encrypt a buffer, consuming it.
			 * @param input Input buffer.
			 * @param output Destination buffer.
			 * @param strategy Native or Hybrid. Default Native.
			 * @return true on success.
			 */
			bool Encrypt(Buffer::ReadOnly& input, Buffer::WriteOnly& output, Strategy strategy = Strategy::Native) const noexcept;

			/**
			 * @brief Encrypt a Consumer.
			 * @param consumer Input consumer.
			 * @param strategy Native or Hybrid. Default Native.
			 * @param mode Copy or move.
			 * @return Consumer with ciphertext.
			 */
			Buffer::Consumer Encrypt(Buffer::Consumer consumer, Strategy strategy = Strategy::Native, ReadMode mode = ReadMode::Move) const noexcept;
			/** @} */

			/**
			 * @name Decrypt
			 * @{
			 */
			/**
			 * @brief Decrypt a byte span. Detects Native vs Hybrid.
			 * @param input Input bytes.
			 * @param output Destination buffer.
			 * @return true on success.
			 */
			bool Decrypt(std::span<const std::byte> input, Buffer::WriteOnly& output) const noexcept;

			/**
			 * @brief Decrypt a read-only buffer (copy). Detects Native vs Hybrid.
			 * @param input Input buffer.
			 * @param output Destination buffer.
			 * @return true on success.
			 */
			bool Decrypt(const Buffer::ReadOnly& input, Buffer::WriteOnly& output) const noexcept;

			/**
			 * @brief Decrypt a buffer, consuming it. Detects Native vs Hybrid.
			 * @param input Input buffer.
			 * @param output Destination buffer.
			 * @return true on success.
			 */
			bool Decrypt(Buffer::ReadOnly& input, Buffer::WriteOnly& output) const noexcept;

			/**
			 * @brief Decrypt a Consumer. Detects Native vs Hybrid.
			 * @param consumer Input consumer.
			 * @param mode Copy or move.
			 * @return Consumer with plaintext.
			 */
			Buffer::Consumer Decrypt(Buffer::Consumer consumer, ReadMode mode = ReadMode::Move) const noexcept;
			/** @} */

		protected:
			KeyPair::Generic::PointerType m_keypair;	///< Shared keypair

			/**
			 * @brief Construct from a keypair pointer.
			 * @param type Cipher.
			 * @param keypair Keypair.
			 */
			inline Asymmetric(enum Type type, KeyPair::Generic::PointerType keypair):
				Generic(type), m_keypair(keypair) {}

			/**
			 * @brief Construct by cloning a keypair.
			 * @param type Cipher.
			 * @param keypair Keypair.
			 */
			inline Asymmetric(enum Type type, const KeyPair::Generic& keypair):
				Generic(type), m_keypair(keypair.Clone()) {}

			/**
			 * @brief Construct by moving a keypair.
			 * @param type Cipher.
			 * @param keypair Keypair.
			 */
			inline Asymmetric(enum Type type, KeyPair::Generic&& keypair):
				Generic(type), m_keypair(keypair.Move()) {}
	};

	/**
	 * @brief Factory from a keypair pointer.
	 * @param type Cipher.
	 * @param keypair Keypair.
	 * @return Crypter pointer.
	 */
	STORMBYTE_CRYPTO_PUBLIC Generic::PointerType Create(enum Type type, KeyPair::Generic::PointerType keypair) noexcept;

	/**
	 * @brief Factory by cloning a keypair.
	 * @param type Cipher.
	 * @param keypair Keypair.
	 * @return Crypter pointer.
	 */
	STORMBYTE_CRYPTO_PUBLIC Generic::PointerType Create(enum Type type, const KeyPair::Generic& keypair) noexcept;

	/**
	 * @brief Factory by moving a keypair.
	 * @param type Cipher.
	 * @param keypair Keypair.
	 * @return Crypter pointer.
	 */
	STORMBYTE_CRYPTO_PUBLIC Generic::PointerType Create(enum Type type, KeyPair::Generic&& keypair) noexcept;
}
