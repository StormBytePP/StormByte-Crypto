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

#include <StormByte/crypto/password.hxx>
#include <StormByte/crypto/visibility.h>

#include <optional>
#include <string>

/**
 * @brief Private key-agreement implementation.
 */
namespace StormByte::Crypto::Implementation::Secret {
	/**
	 * @brief ECDH share (raw path + ASN.1 fallback).
	 * @param privateKey Local private key.
	 * @param peerPublicKeyBase64 Peer public key as Base64.
	 * @param bits Curve size (256 / 384 / 521).
	 * @return Password, or empty.
	 */
	std::optional<Password> ECDHShare(const Password& privateKey,
									const std::string& peerPublicKeyBase64,
									unsigned short bits) noexcept;

	/**
	 * @brief X25519 share.
	 * @param privateKey Local private key.
	 * @param peerPublicKeyBase64 Peer public key as Base64.
	 * @return Password, or empty.
	 */
	std::optional<Password> X25519Share(const Password& privateKey,
										const std::string& peerPublicKeyBase64) noexcept;
}
