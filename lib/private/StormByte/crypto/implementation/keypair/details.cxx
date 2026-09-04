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

#include <StormByte/crypto/implementation/keypair/details.hxx>
#include <base64.h>
#include <filters.h>
namespace StormByte::Crypto::Implementation::KeyPair {
	std::string EncodeSecBlockBase64(const CryptoPP::SecByteBlock& b) noexcept
	{
		std::string out;
		CryptoPP::Base64Encoder enc(new CryptoPP::StringSink(out), false);
		enc.Put(b.data(), b.size());
		enc.MessageEnd();
		return out;
	}
	CryptoPP::SecByteBlock DecodeSecBlockBase64(const std::string& s) noexcept
	{
		CryptoPP::Base64Decoder dec;
		CryptoPP::StringSource ss(s, true, new CryptoPP::Redirector(dec));
		CryptoPP::SecByteBlock b;
		b.resize(dec.MaxRetrievable());
		if (b.size() > 0)
			dec.Get(b.data(), b.size());
		return b;
	}
}
