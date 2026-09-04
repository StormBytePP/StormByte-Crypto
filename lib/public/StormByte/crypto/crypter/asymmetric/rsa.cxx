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

#include <StormByte/crypto/crypter/asymmetric/rsa.hxx>
#include <StormByte/crypto/implementation/crypter/asymmetric/api.hxx>
#include <rsa.h>
using namespace StormByte::Crypto::Crypter;
bool RSA::DoEncrypt(std::span<const std::byte> input, Buffer::WriteOnly& output) const noexcept {
	return Implementation::Crypter::Asymmetric::EncryptAsymmetric<CryptoPP::RSAES_OAEP_SHA_Encryptor, CryptoPP::RSA::PublicKey>(input, m_keypair, output);
}
StormByte::Buffer::Consumer RSA::DoEncrypt(Buffer::Consumer consumer, ReadMode mode) const noexcept {
	return Implementation::Crypter::Asymmetric::EncryptAsymmetric<CryptoPP::RSAES_OAEP_SHA_Encryptor, CryptoPP::RSA::PublicKey>(consumer, m_keypair, mode);
}
bool RSA::DoDecrypt(std::span<const std::byte> input, Buffer::WriteOnly& output) const noexcept {
	return Implementation::Crypter::Asymmetric::DecryptAsymmetric<CryptoPP::RSAES_OAEP_SHA_Decryptor, CryptoPP::RSA::PrivateKey>(input, m_keypair, output);
}
StormByte::Buffer::Consumer RSA::DoDecrypt(Buffer::Consumer consumer, ReadMode mode) const noexcept {
	return Implementation::Crypter::Asymmetric::DecryptAsymmetric<CryptoPP::RSAES_OAEP_SHA_Decryptor, CryptoPP::RSA::PrivateKey>(consumer, m_keypair, mode);
}
