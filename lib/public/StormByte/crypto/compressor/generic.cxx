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

#include <StormByte/crypto/compressor/bzip2.hxx>
#include <StormByte/crypto/compressor/zlib.hxx>
using namespace StormByte::Crypto::Compressor;
bool Generic::DoCompress(Buffer::ReadOnly& input, Buffer::WriteOnly& output, ReadMode mode) const noexcept {
	Buffer::DataType data;
	bool read_ok;
	if (mode == ReadMode::Copy)
		read_ok = input.Read(data);
	else
		read_ok = input.Extract(data);
	if (!read_ok)
		return false;
	return DoCompress(std::span<const std::byte>(data.data(), data.size()), output);
}
bool Generic::DoDecompress(Buffer::ReadOnly& input, Buffer::WriteOnly& output, ReadMode mode) const noexcept {
	Buffer::DataType data;
	bool read_ok;
	if (mode == ReadMode::Copy)
		read_ok = input.Read(data);
	else
		read_ok = input.Extract(data);
	if (!read_ok)
		return false;
	return DoDecompress(std::span<const std::byte>(data.data(), data.size()), output);	
}
namespace StormByte::Crypto::Compressor {
	Generic::PointerType Create(Type type, unsigned short level) noexcept {
		switch (type) {
			case Type::Bzip2:
				return std::make_shared<Bzip2>(level);
			case Type::Zlib:
				return std::make_shared<Zlib>(level);
			default:
				return nullptr;
		}
	}
}
