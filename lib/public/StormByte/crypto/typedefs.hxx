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

#include <StormByte/buffer/generic.hxx>
#include <StormByte/crypto/exception.hxx>
#include <StormByte/expected.hxx>

#include <memory>

/**
 * @namespace Crypto
 * @brief The namespace containing all the cryptographic-related classes.
 */
namespace StormByte::Crypto {
	class Password;

	/**
	 * @enum ReadMode
	 * @brief The types of data operations.
	 */
	enum class ReadMode: unsigned short {
		Copy,	///< Indicates a copy operation
		Move	///< Indicates a move operation
	};

	using ExpectedPassword = StormByte::Expected<Password, Exception>;
}
