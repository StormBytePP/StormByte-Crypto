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

#include <StormByte/crypto/password.hxx>
#include <StormByte/crypto/helpers/secure_content.hxx>
#include <StormByte/crypto/helpers/secure_wipe.hxx>
#include <cstring>
using namespace StormByte::Crypto;
namespace {
	struct SecureContentDeleter {
		void operator()(Helpers::SecureContent* ptr) const noexcept {
			if (ptr) {
				ptr->Wipe();
				delete ptr;
			}
		}
	};
}
Password::Password(std::string value) noexcept {
	const std::size_t n = value.size();
	auto* content = new Helpers::SecureContent(value.data(), n);
	Helpers::SecureWipe(value);
	m_data.reset(content, SecureContentDeleter{});
}
Password::Password(const char* value) noexcept {
	const std::size_t n = value ? std::strlen(value) : 0;
	auto* content = new Helpers::SecureContent(value, n);
	m_data.reset(content, SecureContentDeleter{});
}
Password::Password(const void* data, std::size_t size) noexcept {
	auto* content = new Helpers::SecureContent(data, size);
	m_data.reset(content, SecureContentDeleter{});
}
std::size_t Password::Size() const noexcept {
	return m_data ? m_data->Size() : 0;
}
bool Password::Empty() const noexcept {
	return Size() == 0;
}
Password::operator bool() const noexcept {
	return !Empty();
}
bool Password::operator==(const Password& other) const noexcept {
	if (!m_data || !other.m_data)
		return m_data == other.m_data;
	return m_data->Equal(*other.m_data);
}
bool Password::operator!=(const Password& other) const noexcept {
	return !(*this == other);
}
