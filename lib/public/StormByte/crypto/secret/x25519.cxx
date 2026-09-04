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

#include <StormByte/crypto/secret/x25519.hxx>
#include <StormByte/crypto/implementation/secret/details.hxx>
using namespace StormByte::Crypto::Secret;
std::optional<StormByte::Crypto::Password>
X25519::Share(const std::string& peerPublicKey) const noexcept
{
	if (!m_keypair || !m_keypair->HasPrivateKey())
		return std::nullopt;
	return Implementation::Secret::X25519Share(
		*m_keypair->PrivateKey(), peerPublicKey);
}
std::optional<StormByte::Crypto::Password>
X25519::DeriveSharedSecret(KeyPair::Generic::PointerType keypair,
						const std::string& peerPublicKey) noexcept
{
	if (!keypair || !keypair->HasPrivateKey())
		return std::nullopt;
	return Implementation::Secret::X25519Share(
		*keypair->PrivateKey(), peerPublicKey);
}
