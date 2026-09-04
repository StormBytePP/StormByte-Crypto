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

#include <StormByte/buffer/consumer.hxx>
#include <StormByte/clonable.hxx>
#include <StormByte/crypto/keypair/generic.hxx>

/**
 * @brief Signers of the Crypto module.
 */
namespace StormByte::Crypto::Signer {
	/**
	 * @enum Type
	 * @brief Available signer algorithms.
	 */
	enum class Type {
		DSA,		///< DSA
		ECDSA,		///< ECDSA
		ED25519,	///< Ed25519
		RSA,		///< RSA
	};

	/**
	 * @class Generic
	 * @brief Abstract signer. Concrete algorithms derive from this.
	 */
	class STORMBYTE_CRYPTO_PUBLIC Generic: public StormByte::Clonable<Generic> {
		public:
			/**
			 * @name Construction
			 * @{
			 */
			/**
			 * @brief Copy constructor.
			 * @param other Signer to copy.
			 */
			Generic(const Generic& other) = default;

			/**
			 * @brief Move constructor.
			 * @param other Signer to move.
			 */
			Generic(Generic&& other) noexcept = default;

			/**
			 * @brief Destructor.
			 */
			virtual ~Generic() noexcept = default;

			/**
			 * @brief Copy assignment.
			 * @param other Signer to copy.
			 * @return Reference to this signer.
			 */
			Generic& operator=(const Generic& other) = default;

			/**
			 * @brief Move assignment.
			 * @param other Signer to move.
			 * @return Reference to this signer.
			 */
			Generic& operator=(Generic&& other) noexcept = default;
			/** @} */

			/**
			 * @brief Keypair used to sign and verify.
			 * @return Keypair pointer.
			 */
			KeyPair::Generic::PointerType KeyPair() const noexcept {
				return m_keypair;
			}

			/**
			 * @name Sign
			 * @{
			 */
			/**
			 * @brief Sign a byte span.
			 * @param input Input bytes.
			 * @param output Destination buffer.
			 * @return true on success.
			 */
			inline bool Sign(std::span<const std::byte> input, Buffer::WriteOnly& output) const noexcept {
				return DoSign(input, output);
			}

			/**
			 * @brief Sign a ReadOnly buffer (copy).
			 * @param input Input buffer.
			 * @param output Destination buffer.
			 * @return true on success.
			 */
			inline bool Sign(const Buffer::ReadOnly& input, Buffer::WriteOnly& output) const noexcept {
				return DoSign(const_cast<Buffer::ReadOnly&>(input), output, ReadMode::Copy);
			}

			/**
			 * @brief Sign a ReadOnly buffer (move).
			 * @param input Input buffer.
			 * @param output Destination buffer.
			 * @return true on success.
			 */
			inline bool Sign(Buffer::ReadOnly& input, Buffer::WriteOnly& output) const noexcept {
				return DoSign(input, output, ReadMode::Move);
			}

			/**
			 * @brief Sign a Consumer.
			 * @param consumer Input consumer.
			 * @param mode Copy or move.
			 * @return Consumer with the signature.
			 */
			inline Buffer::Consumer Sign(Buffer::Consumer consumer, ReadMode mode = ReadMode::Move) const noexcept {
				return DoSign(consumer, mode);
			}
			/** @} */

			/**
			 * @name Verify
			 * @{
			 */
			/**
			 * @brief Verify a byte span against a signature.
			 * @param input Input bytes.
			 * @param signature Signature.
			 * @return true if valid.
			 */
			inline bool Verify(std::span<const std::byte> input, const std::string& signature) const noexcept {
				return DoVerify(input, signature);
			}

			/**
			 * @brief Verify a ReadOnly buffer (copy).
			 * @param input Input buffer.
			 * @param signature Signature.
			 * @return true if valid.
			 */
			inline bool Verify(const Buffer::ReadOnly& input, const std::string& signature) const noexcept {
				return DoVerify(const_cast<Buffer::ReadOnly&>(input), signature, ReadMode::Copy);
			}

			/**
			 * @brief Verify a ReadOnly buffer (move).
			 * @param input Input buffer.
			 * @param signature Signature.
			 * @return true if valid.
			 */
			inline bool Verify(Buffer::ReadOnly& input, const std::string& signature) const noexcept {
				return DoVerify(input, signature, ReadMode::Move);
			}

			/**
			 * @brief Verify a Consumer.
			 * @param consumer Input consumer.
			 * @param signature Signature.
			 * @param mode Copy or move.
			 * @return true if valid.
			 */
			inline bool Verify(Buffer::Consumer consumer, const std::string& signature, ReadMode mode = ReadMode::Move) const noexcept {
				return DoVerify(consumer, signature, mode);
			}
			/** @} */

		protected:
			enum Type m_type;							///< Algorithm
			KeyPair::Generic::PointerType m_keypair;	///< Keypair

			/**
			 * @brief Construct from a keypair pointer.
			 * @param type Algorithm.
			 * @param keypair Keypair.
			 */
			inline Generic(enum Type type, KeyPair::Generic::PointerType keypair):
				m_type(type), m_keypair(keypair) {}

			/**
			 * @brief Construct by cloning a keypair.
			 * @param type Algorithm.
			 * @param keypair Keypair.
			 */
			inline Generic(enum Type type, const KeyPair::Generic& keypair):
				m_type(type), m_keypair(keypair.Clone()) {}

			/**
			 * @brief Construct by moving a keypair.
			 * @param type Algorithm.
			 * @param keypair Keypair.
			 */
			inline Generic(enum Type type, KeyPair::Generic&& keypair):
				m_type(type), m_keypair(keypair.Move()) {}

		private:
			/**
			 * @brief Sign a ReadOnly buffer.
			 * @param input Input buffer.
			 * @param output Destination buffer.
			 * @param mode Copy or move.
			 * @return true on success.
			 */
			bool DoSign(Buffer::ReadOnly& input, Buffer::WriteOnly& output, ReadMode mode) const noexcept;

			/**
			 * @brief Sign a byte span.
			 * @param input Input bytes.
			 * @param output Destination buffer.
			 * @return true on success.
			 */
			virtual bool DoSign(std::span<const std::byte> input, Buffer::WriteOnly& output) const noexcept = 0;

			/**
			 * @brief Sign a Consumer.
			 * @param consumer Input consumer.
			 * @param mode Copy or move.
			 * @return Consumer with the signature.
			 */
			virtual Buffer::Consumer DoSign(Buffer::Consumer consumer, ReadMode mode) const noexcept = 0;

			/**
			 * @brief Verify a ReadOnly buffer.
			 * @param input Input buffer.
			 * @param signature Signature.
			 * @param mode Copy or move.
			 * @return true if valid.
			 */
			bool DoVerify(Buffer::ReadOnly& input, const std::string& signature, ReadMode mode) const noexcept;

			/**
			 * @brief Verify a byte span.
			 * @param input Input bytes.
			 * @param signature Signature.
			 * @return true if valid.
			 */
			virtual bool DoVerify(std::span<const std::byte> input, const std::string& signature) const noexcept = 0;

			/**
			 * @brief Verify a Consumer.
			 * @param consumer Input consumer.
			 * @param signature Signature.
			 * @param mode Copy or move.
			 * @return true if valid.
			 */
			virtual bool DoVerify(Buffer::Consumer consumer, const std::string& signature, ReadMode mode) const noexcept = 0;
	};

	/**
	 * @brief Create a signer from a keypair pointer.
	 * @param type Algorithm.
	 * @param keypair Keypair.
	 * @return Signer pointer.
	 */
	STORMBYTE_CRYPTO_PUBLIC Generic::PointerType Create(enum Type type, KeyPair::Generic::PointerType keypair) noexcept;

	/**
	 * @brief Create a signer by cloning a keypair.
	 * @param type Algorithm.
	 * @param keypair Keypair.
	 * @return Signer pointer.
	 */
	STORMBYTE_CRYPTO_PUBLIC Generic::PointerType Create(enum Type type, const KeyPair::Generic& keypair) noexcept;

	/**
	 * @brief Create a signer by moving a keypair.
	 * @param type Algorithm.
	 * @param keypair Keypair.
	 * @return Signer pointer.
	 */
	STORMBYTE_CRYPTO_PUBLIC Generic::PointerType Create(enum Type type, KeyPair::Generic&& keypair) noexcept;
}
