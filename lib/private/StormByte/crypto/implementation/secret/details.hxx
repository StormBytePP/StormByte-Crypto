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

#include <StormByte/crypto/password.hxx>
#include <StormByte/crypto/visibility.h>

#include <optional>
#include <string>

namespace StormByte::Crypto::Implementation::Secret {
	/**
	 * @brief ECDH shared-secret derivation (raw domain path + ASN.1 fallback).
	 * @param privateKey Local private key material.
	 * @param peerPublicKeyBase64 Peer public key (Base64).
	 * @param bits Curve size in bits (256 / 384 / 521).
	 * @return Shared secret as Password, or nullopt on failure.
	 */
	std::optional<Password> ECDHShare(const Password& privateKey,
									const std::string& peerPublicKeyBase64,
									unsigned short bits) noexcept;

	/**
	 * @brief X25519 shared-secret derivation.
	 * @param privateKey Local private key material.
	 * @param peerPublicKeyBase64 Peer public key (Base64).
	 * @return Shared secret as Password, or nullopt on failure.
	 */
	std::optional<Password> X25519Share(const Password& privateKey,
										const std::string& peerPublicKeyBase64) noexcept;
}
