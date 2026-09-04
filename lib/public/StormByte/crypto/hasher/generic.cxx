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

#include <StormByte/crypto/hasher/blake2b.hxx>
#include <StormByte/crypto/hasher/blake2s.hxx>
#include <StormByte/crypto/hasher/sha3_256.hxx>
#include <StormByte/crypto/hasher/sha3_512.hxx>
#include <StormByte/crypto/hasher/sha256.hxx>
#include <StormByte/crypto/hasher/sha512.hxx>
using namespace StormByte::Crypto::Hasher;
bool Generic::DoHash(Buffer::ReadOnly& input, Buffer::WriteOnly& output, ReadMode mode) const noexcept {
	Buffer::DataType data;
	bool read_ok;
	if (mode == ReadMode::Copy)
		read_ok = input.Read(data);
	else
		read_ok = input.Extract(data);
	if (!read_ok)
		return false;
	return DoHash(std::span<const std::byte>(data.data(), data.size()), output);
}
namespace StormByte::Crypto::Hasher {
	Generic::PointerType Create(Type type) noexcept {
		switch (type) {
			case Type::Blake2b:
				return std::make_shared<Blake2b>();
			case Type::Blake2s:
				return std::make_shared<Blake2s>();
			case Type::SHA256:
				return std::make_shared<SHA256>();
			case Type::SHA512:
				return std::make_shared<SHA512>();
			case Type::SHA3_256:
				return std::make_shared<SHA3_256>();
			case Type::SHA3_512:
				return std::make_shared<SHA3_512>();
			default:
				return nullptr;
		}
	}
}
