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

#include <StormByte/buffer/producer.hxx>
#include <StormByte/crypto/typedefs.hxx>
#include <StormByte/crypto/visibility.h>

#include <memory>
#include <span>
#include <string>

/**
 * @brief Private signer implementation.
 */
namespace StormByte::Crypto::Implementation::Signer {
	/**
	 * @struct SignBox
	 * @brief Type-erased streaming signer.
	 */
	struct SignBox {
		virtual ~SignBox() = default;

		/**
		 * @brief Feed one message chunk.
		 * @param in Input bytes.
		 * @return true on success.
		 */
		virtual bool Update(std::span<const std::byte> in) = 0;

		/**
		 * @brief Finish and write the signature.
		 * @param out Destination.
		 * @return true on success.
		 */
		virtual bool Finalize(Buffer::DataType& out) = 0;
	};

	/**
	 * @struct VerifyBox
	 * @brief Type-erased streaming verifier. Call Begin first.
	 */
	struct VerifyBox {
		virtual ~VerifyBox() = default;

		/**
		 * @brief Supply the signature before any Update.
		 * @param signature Signature.
		 * @return true on success.
		 */
		virtual bool Begin(const std::string& signature) = 0;

		/**
		 * @brief Feed one message chunk.
		 * @param in Input bytes.
		 * @return true on success.
		 */
		virtual bool Update(std::span<const std::byte> in) = 0;

		/**
		 * @brief Finish verification.
		 * @return true if valid.
		 */
		virtual bool Finalize() = 0;
	};

	/**
	 * @brief One-shot sign.
	 * @param data Input.
	 * @param output Destination.
	 * @param box Engine.
	 * @return true on success.
	 */
	bool SignSpan(std::span<const std::byte> data,
				Buffer::WriteOnly& output,
				std::unique_ptr<SignBox> box) noexcept;

	/**
	 * @brief Streaming sign.
	 * @param consumer Input consumer.
	 * @param mode Copy or move.
	 * @param box Engine.
	 * @return Consumer with the signature.
	 */
	Buffer::Consumer SignStream(Buffer::Consumer consumer,
								ReadMode mode,
								std::unique_ptr<SignBox> box) noexcept;

	/**
	 * @brief One-shot verify.
	 * @param data Input.
	 * @param signature Signature.
	 * @param box Engine.
	 * @return true if valid.
	 */
	bool VerifySpan(std::span<const std::byte> data,
					const std::string& signature,
					std::unique_ptr<VerifyBox> box) noexcept;

	/**
	 * @brief Streaming verify.
	 * @param consumer Input consumer.
	 * @param mode Copy or move.
	 * @param signature Signature.
	 * @param box Engine.
	 * @return true if valid.
	 */
	bool VerifyStream(Buffer::Consumer consumer,
					ReadMode mode,
					const std::string& signature,
					std::unique_ptr<VerifyBox> box) noexcept;
}
