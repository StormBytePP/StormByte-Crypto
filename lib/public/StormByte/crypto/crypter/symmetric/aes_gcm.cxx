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

#include <StormByte/crypto/crypter/symmetric/aes_gcm.hxx>
#include <StormByte/crypto/implementation/crypter/symmetric/api.hxx>
#include <aes.h>
using namespace StormByte::Crypto::Crypter;
bool AES_GCM::DoEncrypt(std::span<const std::byte> input, Buffer::WriteOnly& output) const noexcept {
	return Implementation::Crypter::Symmetric::EncryptGCM<CryptoPP::AES, CryptoPP::GCM<CryptoPP::AES>::Encryption, CryptoPP::SHA256>(input, m_password, output, 16, 12);
}
StormByte::Buffer::Consumer AES_GCM::DoEncrypt(Buffer::Consumer consumer, ReadMode mode) const noexcept {
	return Implementation::Crypter::Symmetric::EncryptGCM<CryptoPP::AES, CryptoPP::GCM<CryptoPP::AES>::Encryption, CryptoPP::SHA256>(consumer, m_password, mode, 16, 12);
}
bool AES_GCM::DoDecrypt(std::span<const std::byte> input, Buffer::WriteOnly& output) const noexcept {
	return Implementation::Crypter::Symmetric::DecryptGCM<CryptoPP::AES, CryptoPP::GCM<CryptoPP::AES>::Decryption, CryptoPP::SHA256>(input, m_password, output, 16, 12);
}
StormByte::Buffer::Consumer AES_GCM::DoDecrypt(Buffer::Consumer consumer, ReadMode mode) const noexcept {
	return Implementation::Crypter::Symmetric::DecryptGCM<CryptoPP::AES, CryptoPP::GCM<CryptoPP::AES>::Decryption, CryptoPP::SHA256>(consumer, m_password, mode, 16, 12);
}
