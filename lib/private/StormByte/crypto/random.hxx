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

#include <StormByte/crypto/visibility.h>

#include <osrng.h>

/**
 * @brief Crypto module of the StormByte suite.
 */
namespace StormByte::Crypto {
	/**
	 * @brief Process-wide AutoSeededRandomPool.
	 * @return RNG reference.
	 */
	STORMBYTE_CRYPTO_PRIVATE CryptoPP::AutoSeededRandomPool& RNG();
}
