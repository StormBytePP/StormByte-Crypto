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

#include <StormByte/crypto/crypter/symmetric/chachapoly.hxx>
#include <StormByte/crypto/implementation/crypter/symmetric/api.hxx>
#include <chachapoly.h>
using namespace StormByte::Crypto::Crypter;
bool ChaChaPoly::DoEncrypt(std::span<const std::byte> input, Buffer::WriteOnly& output) const noexcept {
	return Implementation::Crypter::Symmetric::EncryptAEAD<CryptoPP::ChaCha20Poly1305, CryptoPP::ChaCha20Poly1305::Encryption, CryptoPP::SHA256>(input, m_password, output, 16, 12, 32);
}
StormByte::Buffer::Consumer ChaChaPoly::DoEncrypt(Buffer::Consumer consumer, ReadMode mode) const noexcept {
	return Implementation::Crypter::Symmetric::EncryptAEAD<CryptoPP::ChaCha20Poly1305, CryptoPP::ChaCha20Poly1305::Encryption, CryptoPP::SHA256>(consumer, m_password, mode, 16, 12, 32);
}
bool ChaChaPoly::DoDecrypt(std::span<const std::byte> input, Buffer::WriteOnly& output) const noexcept {
	return Implementation::Crypter::Symmetric::DecryptAEAD<CryptoPP::ChaCha20Poly1305, CryptoPP::ChaCha20Poly1305::Decryption, CryptoPP::SHA256>(input, m_password, output, 16, 12, 32);
}
StormByte::Buffer::Consumer ChaChaPoly::DoDecrypt(Buffer::Consumer consumer, ReadMode mode) const noexcept {
	return Implementation::Crypter::Symmetric::DecryptAEAD<CryptoPP::ChaCha20Poly1305, CryptoPP::ChaCha20Poly1305::Decryption, CryptoPP::SHA256>(consumer, m_password, mode, 16, 12, 32);
}
