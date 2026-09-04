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

#include <StormByte/crypto/crypter/symmetric/serpent.hxx>
#include <StormByte/crypto/implementation/crypter/symmetric/api.hxx>
#include <serpent.h>
using namespace StormByte::Crypto::Crypter;
bool Serpent::DoEncrypt(std::span<const std::byte> input, Buffer::WriteOnly& output) const noexcept {
	return Implementation::Crypter::Symmetric::EncryptCBC<CryptoPP::Serpent, CryptoPP::CBC_Mode<CryptoPP::Serpent>::Encryption, CryptoPP::SHA256>(input, m_password, output, 16, CryptoPP::Serpent::BLOCKSIZE);
}
StormByte::Buffer::Consumer Serpent::DoEncrypt(Buffer::Consumer consumer, ReadMode mode) const noexcept {
	return Implementation::Crypter::Symmetric::EncryptCBC<CryptoPP::Serpent, CryptoPP::CBC_Mode<CryptoPP::Serpent>::Encryption, CryptoPP::SHA256>(consumer, m_password, mode, 16, CryptoPP::Serpent::BLOCKSIZE);
}
bool Serpent::DoDecrypt(std::span<const std::byte> input, Buffer::WriteOnly& output) const noexcept {
	return Implementation::Crypter::Symmetric::DecryptCBC<CryptoPP::Serpent, CryptoPP::CBC_Mode<CryptoPP::Serpent>::Decryption, CryptoPP::SHA256>(input, m_password, output, 16, CryptoPP::Serpent::BLOCKSIZE);
}
StormByte::Buffer::Consumer Serpent::DoDecrypt(Buffer::Consumer consumer, ReadMode mode) const noexcept {
	return Implementation::Crypter::Symmetric::DecryptCBC<CryptoPP::Serpent, CryptoPP::CBC_Mode<CryptoPP::Serpent>::Decryption, CryptoPP::SHA256>(consumer, m_password, mode, 16, CryptoPP::Serpent::BLOCKSIZE);
}
