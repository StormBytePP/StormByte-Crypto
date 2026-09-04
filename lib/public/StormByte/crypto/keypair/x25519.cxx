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

#include <StormByte/crypto/helpers/secure_wipe.hxx>
#include <StormByte/crypto/keypair/x25519.hxx>
#include <StormByte/crypto/implementation/keypair/api.hxx>
#include <StormByte/crypto/password.hxx>
#include <StormByte/crypto/random.hxx>
#include <xed25519.h>
using namespace StormByte::Crypto::KeyPair;
X25519::PointerType X25519::Generate(unsigned short /*bits*/) noexcept {
	try {
		CryptoPP::x25519 agreement;
		CryptoPP::SecByteBlock priv(agreement.PrivateKeyLength());
		CryptoPP::SecByteBlock pub(agreement.PublicKeyLength());
		agreement.GenerateKeyPair(RNG(), priv, pub);
		auto pubStr = Implementation::KeyPair::EncodeSecBlockBase64(pub);
		Password privPwd = Implementation::KeyPair::PasswordFromSecBlock(priv);
		Helpers::SecureWipe(pub);
		return std::make_shared<X25519>(
			std::move(pubStr),
			std::move(privPwd)
		);
	} catch (...) {
		return nullptr;
	}
}
