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

#include <StormByte/crypto/visibility.h>

#include <osrng.h>

/**
 * @namespace Crypto
 * @brief The namespace containing all the cryptographic-related classes.
 */
namespace StormByte::Crypto {
	/**
	 * @brief Get the global RNG instance.
	 * @return Reference to the global AutoSeededRandomPool instance.
	 */
	STORMBYTE_CRYPTO_PRIVATE CryptoPP::AutoSeededRandomPool& RNG();
}
