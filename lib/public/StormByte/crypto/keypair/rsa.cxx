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

#include <StormByte/crypto/keypair/rsa.hxx>
#include <StormByte/crypto/implementation/keypair/api.hxx>
#include <StormByte/crypto/password.hxx>
#include <StormByte/crypto/random.hxx>
#include <rsa.h>
using namespace StormByte::Crypto::KeyPair;
RSA::PointerType RSA::Generate(unsigned short key_size) noexcept {
	if (key_size != 1024 && key_size != 2048 && key_size != 3072 && key_size != 4096)
		return nullptr;
	try {
		CryptoPP::RSA::PrivateKey privateKey;
		privateKey.GenerateRandomWithKeySize(RNG(), key_size);
		CryptoPP::RSA::PublicKey publicKey;
		publicKey.AssignFrom(privateKey);
		return std::make_shared<RSA>(
			Implementation::KeyPair::SerializeKey(publicKey),
			Implementation::KeyPair::SerializeKeyBinary(privateKey)
		);
	} catch (...) {
		return nullptr;
	}
}
