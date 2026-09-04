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

#include <StormByte/crypto/keypair/ecc.hxx>
#include <StormByte/crypto/implementation/keypair/api.hxx>
#include <StormByte/crypto/password.hxx>
#include <StormByte/crypto/random.hxx>
#include <eccrypto.h>
#include <oids.h>
using namespace StormByte::Crypto::KeyPair;
ECC::PointerType ECC::Generate(unsigned short bits) noexcept {
	try {
		CryptoPP::OID curve;
		switch (bits) {
			case 256:
				curve = CryptoPP::ASN1::secp256r1();
				break;
			case 384:
				curve = CryptoPP::ASN1::secp384r1();
				break;
			case 521:
				curve = CryptoPP::ASN1::secp521r1();
				break;
			default:
				return nullptr;
		}
		CryptoPP::ECIES<CryptoPP::ECP>::Decryptor decryptor(RNG(), curve);
		CryptoPP::ECIES<CryptoPP::ECP>::Encryptor encryptor(decryptor);
		return std::make_shared<ECC>(
			Implementation::KeyPair::SerializeKey(encryptor.GetPublicKey()),
			Implementation::KeyPair::SerializeKeyBinary(decryptor.GetPrivateKey())
		);
	} catch (...) {
		return nullptr;
	}
}
