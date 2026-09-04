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

#include <StormByte/crypto/signer/ecdsa.hxx>
#include <StormByte/crypto/implementation/signer/api.hxx>
#include <eccrypto.h>
using namespace StormByte::Crypto::Signer;
using StormByte::Buffer::WriteOnly;
using StormByte::Buffer::Consumer;
bool ECDSA::DoSign(std::span<const std::byte> data, WriteOnly& output) const noexcept {
	return Implementation::Signer::Sign<CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::Signer, CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey>(
		data, m_keypair, output);
}
Consumer ECDSA::DoSign(Consumer consumer, ReadMode mode) const noexcept {
	return Implementation::Signer::Sign<CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::Signer, CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey>(
		consumer, m_keypair, mode);
}
bool ECDSA::DoVerify(std::span<const std::byte> data, const std::string& signature) const noexcept {
	return Implementation::Signer::Verify<CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::Verifier, CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PublicKey>(
		data, signature, m_keypair);
}
bool ECDSA::DoVerify(Consumer consumer, const std::string& signature, ReadMode mode) const noexcept {
	return Implementation::Signer::Verify<CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::Verifier, CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PublicKey>(
		consumer, signature, m_keypair, mode);
}
