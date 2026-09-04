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
#include <StormByte/crypto/keypair/ed25519.hxx>
#include <StormByte/crypto/implementation/keypair/api.hxx>
#include <StormByte/crypto/password.hxx>
#include <StormByte/crypto/random.hxx>
#include <xed25519.h>
#include <queue.h>
using namespace StormByte::Crypto::KeyPair;
ED25519::PointerType ED25519::Generate(unsigned short /*bits*/) noexcept {
	try {
		CryptoPP::ed25519::Signer signer(RNG());
		CryptoPP::ed25519::Verifier verifier(signer);
		CryptoPP::ByteQueue pubQueue;
		verifier.GetPublicKey().Save(pubQueue);
		CryptoPP::SecByteBlock pub(pubQueue.CurrentSize());
		pubQueue.Get(pub.data(), pub.size());
		auto pubStr = Implementation::KeyPair::EncodeSecBlockBase64(pub);
		Helpers::SecureWipe(pub);
		CryptoPP::ByteQueue privQueue;
		signer.GetPrivateKey().Save(privQueue);
		CryptoPP::SecByteBlock priv(privQueue.CurrentSize());
		privQueue.Get(priv.data(), priv.size());
		Password privPwd = Implementation::KeyPair::PasswordFromSecBlock(priv);
		return std::make_shared<ED25519>(
			std::move(pubStr),
			std::move(privPwd)
		);
	} catch (...) {
		return nullptr;
	}
}
