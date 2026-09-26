/*
 * Copyright (C) 2024-2026 David C. Manuelda (StormBytePP)
 *
 * This file is part of StormByte-Crypto.
 *
 * StormByte-Crypto original source is dual-licensed:
 *
 * 1. GNU Lesser General Public License v3.0 (or later)
 *    You may redistribute and/or modify this file under the terms of the
 *    GNU Lesser General Public License as published by the Free Software
 *    Foundation, either version 3 of the License, or (at your option)
 *    any later version.
 *
 * 2. Commercial license
 *    Alternatively, this file may be used under the terms of a commercial
 *    license agreement with the copyright holder
 *    (David C. Manuelda <StormByte@gmail.com>).
 *
 * Both licenses apply only to original StormByte-Crypto source in this
 * repository. They do not cover other StormByte modules or any third-party
 * material shipped with this repository (including everything under
 * thirdparty/, in particular Crypto++, bundled libbzip2, the StormByte-Buffer
 * tree and the StormByte suite it vendors), which remains under its own license.
 *
 * Neither license grants any patent rights. Any patent licenses required
 * to use this software or third-party components must be obtained separately
 * from the patent holders.
 *
 * StormByte-Crypto is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * version 3 along with StormByte-Crypto. If not, see
 * <https://www.gnu.org/licenses/lgpl-3.0.html>.
 *
 * SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-StormByte-Commercial
 */

#include <StormByte/crypto/signer/dsa.hxx>
#include <StormByte/crypto/signer/ecdsa.hxx>
#include <StormByte/crypto/signer/ed25519.hxx>
#include <StormByte/crypto/signer/rsa.hxx>
using namespace StormByte::Crypto::Signer;
bool Generic::DoSign(Buffer::ReadOnly& input, Buffer::WriteOnly& output, ReadMode mode) const noexcept {
	Buffer::DataType data;
	bool read_ok;
	if (mode == ReadMode::Copy)
		read_ok = input.Read(data);
	else
		read_ok = input.Extract(data);
	if (!read_ok)
		return false;
	return DoSign(std::span<const std::byte>(data.data(), data.size()), output);
}

bool Generic::DoVerify(Buffer::ReadOnly& input, const std::string& signature, ReadMode mode) const noexcept {
	Buffer::DataType data;
	bool read_ok;
	if (mode == ReadMode::Copy)
		read_ok = input.Read(data);
	else
		read_ok = input.Extract(data);
	if (!read_ok)
		return false;
	return DoVerify(std::span<const std::byte>(data.data(), data.size()), signature);
}

namespace StormByte::Crypto::Signer {
	Generic::PointerType Create(Type type, KeyPair::Generic::PointerType keypair) noexcept {
		if (!keypair)
			return nullptr;
		switch (type) {
			case Type::DSA:
				if (keypair->Type() != KeyPair::Type::DSA)
					return nullptr;
				return std::make_shared<DSA>(keypair);
			case Type::ECDSA:
				if (keypair->Type() != KeyPair::Type::ECDSA)
					return nullptr;
				return std::make_shared<ECDSA>(keypair);
			case Type::ED25519:
				if (keypair->Type() != KeyPair::Type::ED25519)
					return nullptr;
				return std::make_shared<ED25519>(keypair);
			case Type::RSA:
				if (keypair->Type() != KeyPair::Type::RSA)
					return nullptr;
				return std::make_shared<RSA>(keypair);
			default:
				return nullptr;
		}
	}

	Generic::PointerType Create(Type type, const KeyPair::Generic& keypair) noexcept {
		return Create(type, keypair.Clone());
	}

	Generic::PointerType Create(Type type, KeyPair::Generic&& keypair) noexcept {
		return Create(type, keypair.Move());
	}
}
