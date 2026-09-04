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

#include <StormByte/crypto/crypter/asymmetric/ecc.hxx>
#include <StormByte/crypto/implementation/crypter/asymmetric/api.hxx>
#include <eccrypto.h>
using ECIES = CryptoPP::ECIES<CryptoPP::ECP>;
using namespace StormByte::Crypto::Crypter;
bool ECC::DoEncrypt(std::span<const std::byte> input, Buffer::WriteOnly& output) const noexcept {
	return Implementation::Crypter::Asymmetric::EncryptAsymmetric<ECIES::Encryptor, ECIES::PublicKey>(input, m_keypair, output);
}
StormByte::Buffer::Consumer ECC::DoEncrypt(Buffer::Consumer consumer, ReadMode mode) const noexcept {
	return Implementation::Crypter::Asymmetric::EncryptAsymmetric<ECIES::Encryptor, ECIES::PublicKey>(consumer, m_keypair, mode);
}
bool ECC::DoDecrypt(std::span<const std::byte> input, Buffer::WriteOnly& output) const noexcept {
	return Implementation::Crypter::Asymmetric::DecryptAsymmetric<ECIES::Decryptor, ECIES::PrivateKey>(input, m_keypair, output);
}
StormByte::Buffer::Consumer ECC::DoDecrypt(Buffer::Consumer consumer, ReadMode mode) const noexcept {
	return Implementation::Crypter::Asymmetric::DecryptAsymmetric<ECIES::Decryptor, ECIES::PrivateKey>(consumer, m_keypair, mode);
}
