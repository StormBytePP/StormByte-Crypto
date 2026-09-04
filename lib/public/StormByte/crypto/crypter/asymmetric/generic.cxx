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
#include <StormByte/crypto/crypter/asymmetric/rsa.hxx>
#include <StormByte/crypto/implementation/crypter/asymmetric/api.hxx>
#include <StormByte/crypto/keypair/ecc.hxx>
#include <StormByte/crypto/keypair/rsa.hxx>
#include <rsa.h>
#include <eccrypto.h>
using ECIES = CryptoPP::ECIES<CryptoPP::ECP>;
using StormByte::Buffer::Consumer;
using StormByte::Buffer::DataType;
using StormByte::Buffer::Producer;
using StormByte::Buffer::WriteOnly;
using StormByte::Buffer::ReadOnly;
namespace StormByte::Crypto::Crypter {
	Generic::PointerType Create(enum Type type, KeyPair::Generic::PointerType keypair) noexcept
	{
		if (!keypair)
			return nullptr;
		switch (type) {
			case Type::ECC:
				if (keypair->Type() != KeyPair::Type::ECC)
					return nullptr;
				return std::make_shared<ECC>(keypair);
			case Type::RSA:
				if (keypair->Type() != KeyPair::Type::RSA)
					return nullptr;
				return std::make_shared<RSA>(keypair);
			default:
				return nullptr;
		}
	}
	Generic::PointerType Create(enum Type type, const KeyPair::Generic& keypair) noexcept
	{
		return Create(type, keypair.Clone());
	}
	Generic::PointerType Create(enum Type type, KeyPair::Generic&& keypair) noexcept
	{
		return Create(type, keypair.Move());
	}
	// -------------------------------------------------------------------------
	// Encrypt overloads with Strategy
	// -------------------------------------------------------------------------
	bool Asymmetric::Encrypt(std::span<const std::byte> input,
							WriteOnly& output,
							Strategy strategy) const noexcept
	{
		if (strategy == Strategy::Native)
			return DoEncrypt(input, output);
		namespace Impl = Implementation::Crypter::Asymmetric;
		if (Type() == Type::RSA) {
			return Impl::EncryptAsymmetricBlockEnvelope<
				CryptoPP::RSAES_OAEP_SHA_Encryptor,
				CryptoPP::RSA::PublicKey>(input, m_keypair, output);
		}
		if (Type() == Type::ECC) {
			return Impl::EncryptAsymmetricBlockEnvelope<
				ECIES::Encryptor,
				ECIES::PublicKey>(input, m_keypair, output);
		}
		return false;
	}
	bool Asymmetric::Encrypt(const ReadOnly& input,
							WriteOnly& output,
							Strategy strategy) const noexcept
	{
		DataType data;
		if (!const_cast<ReadOnly&>(input).Read(data))
			return false;
		return Encrypt(std::span<const std::byte>(data.data(), data.size()), output, strategy);
	}
	bool Asymmetric::Encrypt(ReadOnly& input,
							WriteOnly& output,
							Strategy strategy) const noexcept
	{
		DataType data;
		if (!input.Extract(data))
			return false;
		return Encrypt(std::span<const std::byte>(data.data(), data.size()), output, strategy);
	}
	Consumer Asymmetric::Encrypt(Consumer consumer,
								Strategy strategy,
								ReadMode mode) const noexcept
	{
		if (strategy == Strategy::Native)
			return DoEncrypt(std::move(consumer), mode);
		namespace Impl = Implementation::Crypter::Asymmetric;
		if (Type() == Type::RSA) {
			return Impl::EncryptAsymmetricBlockEnvelope<
				CryptoPP::RSAES_OAEP_SHA_Encryptor,
				CryptoPP::RSA::PublicKey>(std::move(consumer), m_keypair, mode);
		}
		if (Type() == Type::ECC) {
			return Impl::EncryptAsymmetricBlockEnvelope<
				ECIES::Encryptor,
				ECIES::PublicKey>(std::move(consumer), m_keypair, mode);
		}
		Producer producer;
		producer.SetError();
		return producer.Consumer();
	}
	// -------------------------------------------------------------------------
	// Decrypt overloads (auto-detect Native vs Hybrid)
	// -------------------------------------------------------------------------
	bool Asymmetric::Decrypt(std::span<const std::byte> input,
							WriteOnly& output) const noexcept
	{
		namespace Impl = Implementation::Crypter::Asymmetric;
		bool hybridOk = false;
		if (Type() == Type::RSA) {
			hybridOk = Impl::DecryptAsymmetricBlockEnvelope<
				CryptoPP::RSAES_OAEP_SHA_Decryptor,
				CryptoPP::RSA::PrivateKey>(input, m_keypair, output);
		} else if (Type() == Type::ECC) {
			hybridOk = Impl::DecryptAsymmetricBlockEnvelope<
				ECIES::Decryptor,
				ECIES::PrivateKey>(input, m_keypair, output);
		}
		if (hybridOk)
			return true;
		return DoDecrypt(input, output);
	}
	bool Asymmetric::Decrypt(const ReadOnly& input,
							WriteOnly& output) const noexcept
	{
		DataType data;
		if (!const_cast<ReadOnly&>(input).Read(data))
			return false;
		return Decrypt(std::span<const std::byte>(data.data(), data.size()), output);
	}
	bool Asymmetric::Decrypt(ReadOnly& input,
							WriteOnly& output) const noexcept
	{
		DataType data;
		if (!input.Extract(data))
			return false;
		return Decrypt(std::span<const std::byte>(data.data(), data.size()), output);
	}
	Consumer Asymmetric::Decrypt(Consumer consumer, ReadMode mode) const noexcept
	{
		namespace Impl = Implementation::Crypter::Asymmetric;
		DataType headerPeek;
		if (!consumer.Peek(4, headerPeek) || headerPeek.size() < 4)
			return DoDecrypt(std::move(consumer), mode);
		const uint32_t possibleEskLen =
			(static_cast<uint32_t>(std::to_integer<unsigned char>(headerPeek[0])) << 24) |
			(static_cast<uint32_t>(std::to_integer<unsigned char>(headerPeek[1])) << 16) |
			(static_cast<uint32_t>(std::to_integer<unsigned char>(headerPeek[2])) << 8)  |
			(static_cast<uint32_t>(std::to_integer<unsigned char>(headerPeek[3])));
		const bool looksLikeHybrid = (possibleEskLen >= 32 && possibleEskLen <= 512);
		if (looksLikeHybrid) {
			if (Type() == Type::RSA) {
				return Impl::DecryptAsymmetricBlockEnvelope<
					CryptoPP::RSAES_OAEP_SHA_Decryptor,
					CryptoPP::RSA::PrivateKey>(std::move(consumer), m_keypair, mode);
			}
			if (Type() == Type::ECC) {
				return Impl::DecryptAsymmetricBlockEnvelope<
					ECIES::Decryptor,
					ECIES::PrivateKey>(std::move(consumer), m_keypair, mode);
			}
		}
		return DoDecrypt(std::move(consumer), mode);
	}
}
