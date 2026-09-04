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

#include <StormByte/crypto/vault.hxx>
using namespace StormByte::Crypto;
Vault::~Vault() noexcept {
	Clear();
}
Vault::Vault(Vault&& other) noexcept
	: m_passwords(std::move(other.m_passwords))
{
	other.m_passwords.clear();
}
Vault& Vault::operator=(Vault&& other) noexcept {
	if (this != &other) {
		Clear();
		m_passwords = std::move(other.m_passwords);
		other.m_passwords.clear();
	}
	return *this;
}
void Vault::Store(std::string name, Password password) noexcept {
	m_passwords.insert_or_assign(std::move(name), std::move(password));
}
ExpectedPassword Vault::Get(const std::string& name) const noexcept {
	auto it = m_passwords.find(name);
	if (it == m_passwords.end()) {
		return StormByte::Unexpected<Exception>("Vault", "Password '{}' not found", name);
	}
	return it->second;
}
bool Vault::Contains(const std::string& name) const noexcept {
	return m_passwords.contains(name);
}
void Vault::Remove(const std::string& name) noexcept {
	m_passwords.erase(name);
}
void Vault::Clear() noexcept {
	m_passwords.clear();
}
std::size_t Vault::Size() const noexcept {
	return m_passwords.size();
}
bool Vault::Empty() const noexcept {
	return m_passwords.empty();
}
