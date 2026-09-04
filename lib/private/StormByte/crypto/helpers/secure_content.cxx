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

#include <StormByte/crypto/helpers/secure_content.hxx>
#include <cstring>
using namespace StormByte::Crypto::Helpers;
SecureContent::SecureContent(const void* data, std::size_t size) noexcept
	: m_block(size)
{
	if (size > 0 && data)
		std::memcpy(m_block.data(), data, size);
}
void SecureContent::Wipe() noexcept {
	if (m_block.size() > 0)
		m_block.CleanNew(0);
}
std::size_t SecureContent::Size() const noexcept {
	return m_block.size();
}
const unsigned char* SecureContent::Data() const noexcept {
	return m_block.data();
}
bool SecureContent::Equal(const SecureContent& other) const noexcept {
	if (m_block.size() != other.m_block.size())
		return false;
	unsigned char diff = 0;
	for (std::size_t i = 0; i < m_block.size(); ++i)
		diff |= static_cast<unsigned char>(m_block[i] ^ other.m_block[i]);
	return diff == 0;
}
