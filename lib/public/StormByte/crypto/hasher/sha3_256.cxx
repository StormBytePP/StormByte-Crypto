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

#include <StormByte/crypto/hasher/sha3_256.hxx>
#include <StormByte/crypto/implementation/hasher/api.hxx>
#include <sha3.h>
using StormByte::Buffer::Consumer;
using StormByte::Buffer::Producer;
using StormByte::Buffer::WriteOnly;
using namespace StormByte::Crypto::Hasher;
bool SHA3_256::DoHash(std::span<const std::byte> dataSpan, WriteOnly& output) const noexcept {
	return Implementation::Hasher::Hash<CryptoPP::SHA3_256>(dataSpan, output);
}
Consumer SHA3_256::DoHash(Consumer consumer, ReadMode mode) const noexcept {
	return Implementation::Hasher::Hash<CryptoPP::SHA3_256>(consumer, mode);
}
