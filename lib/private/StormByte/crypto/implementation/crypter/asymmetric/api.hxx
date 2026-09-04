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

#pragma once

#include <StormByte/crypto/implementation/crypter/asymmetric/details.hxx>
#include <StormByte/crypto/implementation/keypair/api.hxx>
#include <StormByte/crypto/keypair/generic.hxx>
#include <StormByte/crypto/password.hxx>
#include <StormByte/crypto/random.hxx>
#include <StormByte/crypto/typedefs.hxx>
#include <StormByte/crypto/visibility.h>

#include <filters.h>
#include <memory>
#include <span>

namespace StormByte::Crypto::Implementation::Crypter::Asymmetric {
	namespace {
		template<typename CryptorT, typename KeyT>
		struct EncryptBox final : PkBox {
			std::unique_ptr<KeyT> key;

			explicit EncryptBox(StormByte::Crypto::KeyPair::Generic::PointerType keypair)
			{
				if (!keypair)
					return;
				auto keyRes = KeyPair::DeserializeKey<KeyT>(keypair->PublicKey());
				if (!keyRes)
					return;
				key = std::make_unique<KeyT>(std::move(*keyRes));
				if (!key->Validate(RNG(), 3))
					key.reset();
			}

			bool Transform(std::span<const std::byte> in, Buffer::DataType& out) override
			{
				if (!key)
					return false;
				try {
					CryptorT encryptor(*key);
					CryptoPP::PK_EncryptorFilter pkf(
						RNG(), encryptor,
						new CryptoPP::StringSinkTemplate<Buffer::DataType>(out)
					);
					pkf.Put(reinterpret_cast<const CryptoPP::byte*>(in.data()), in.size_bytes());
					pkf.MessageEnd();
					return true;
				} catch (...) {
					return false;
				}
			}
		};

		template<typename DecryptorT, typename KeyT>
		struct DecryptBox final : PkBox {
			std::unique_ptr<KeyT> key;

			explicit DecryptBox(StormByte::Crypto::KeyPair::Generic::PointerType keypair)
			{
				if (!keypair || !keypair->HasPrivateKey())
					return;
				auto keyRes = KeyPair::DeserializeKey<KeyT>(*keypair->PrivateKey());
				if (!keyRes)
					return;
				key = std::make_unique<KeyT>(std::move(*keyRes));
				if (!key->Validate(RNG(), 3))
					key.reset();
			}

			explicit DecryptBox(const Password& privKey)
			{
				auto keyRes = KeyPair::DeserializeKey<KeyT>(privKey);
				if (!keyRes)
					return;
				key = std::make_unique<KeyT>(std::move(*keyRes));
				if (!key->Validate(RNG(), 3))
					key.reset();
			}

			bool Transform(std::span<const std::byte> in, Buffer::DataType& out) override
			{
				if (!key)
					return false;
				try {
					DecryptorT decryptor(*key);
					CryptoPP::PK_DecryptorFilter pkdf(
						RNG(), decryptor,
						new CryptoPP::StringSinkTemplate<Buffer::DataType>(out)
					);
					pkdf.Put(reinterpret_cast<const CryptoPP::byte*>(in.data()), in.size_bytes());
					pkdf.MessageEnd();
					return true;
				} catch (...) {
					return false;
				}
			}
		};

	} // namespace

	template<typename CryptorT, typename PublicKeyT>
	bool EncryptAsymmetric(std::span<const std::byte> data,
						StormByte::Crypto::KeyPair::Generic::PointerType keypair,
						Buffer::WriteOnly& output) noexcept
	{
		return NativeProcessSpan(
			data, output,
			std::make_unique<EncryptBox<CryptorT, PublicKeyT>>(std::move(keypair)));
	}

	template<typename CryptorT, typename PublicKeyT>
	Buffer::Consumer EncryptAsymmetric(Buffer::Consumer consumer,
									StormByte::Crypto::KeyPair::Generic::PointerType keypair,
									ReadMode mode) noexcept
	{
		return NativeProcessStream(
			std::move(consumer), mode,
			std::make_unique<EncryptBox<CryptorT, PublicKeyT>>(std::move(keypair)));
	}

	template<typename EncryptorT, typename PublicKeyT>
	bool EncryptAsymmetricBlockEnvelope(std::span<const std::byte> data,
										StormByte::Crypto::KeyPair::Generic::PointerType keypair,
										Buffer::WriteOnly& output) noexcept
	{
		return HybridEncryptSpan(
			data, output,
			std::make_unique<EncryptBox<EncryptorT, PublicKeyT>>(std::move(keypair)));
	}

	template<typename EncryptorT, typename PublicKeyT>
	Buffer::Consumer EncryptAsymmetricBlockEnvelope(Buffer::Consumer consumer,
													StormByte::Crypto::KeyPair::Generic::PointerType keypair,
													ReadMode mode) noexcept
	{
		return HybridEncryptStream(
			std::move(consumer), mode,
			std::make_unique<EncryptBox<EncryptorT, PublicKeyT>>(std::move(keypair)));
	}

	template<typename DecryptorT, typename PrivateKeyT>
	bool DecryptAsymmetric(std::span<const std::byte> data,
						StormByte::Crypto::KeyPair::Generic::PointerType keypair,
						Buffer::WriteOnly& output) noexcept
	{
		return NativeProcessSpan(
			data, output,
			std::make_unique<DecryptBox<DecryptorT, PrivateKeyT>>(std::move(keypair)));
	}

	template<typename DecryptorT, typename PrivateKeyT>
	Buffer::Consumer DecryptAsymmetric(Buffer::Consumer consumer,
									StormByte::Crypto::KeyPair::Generic::PointerType keypair,
									ReadMode mode) noexcept
	{
		if (!keypair || !keypair->HasPrivateKey()) {
			Buffer::Producer producer;
			producer.SetError();
			return producer.Consumer();
		}
		return NativeProcessStream(
			std::move(consumer), mode,
			std::make_unique<DecryptBox<DecryptorT, PrivateKeyT>>(*keypair->PrivateKey()));
	}

	template<typename DecryptorT, typename PrivateKeyT>
	bool DecryptAsymmetricBlockEnvelope(std::span<const std::byte> data,
										StormByte::Crypto::KeyPair::Generic::PointerType keypair,
										Buffer::WriteOnly& output) noexcept
	{
		return HybridDecryptSpan(
			data, output,
			std::make_unique<DecryptBox<DecryptorT, PrivateKeyT>>(std::move(keypair)));
	}

	template<typename DecryptorT, typename PrivateKeyT>
	Buffer::Consumer DecryptAsymmetricBlockEnvelope(Buffer::Consumer consumer,
													StormByte::Crypto::KeyPair::Generic::PointerType keypair,
													ReadMode mode) noexcept
	{
		if (!keypair || !keypair->HasPrivateKey()) {
			Buffer::Producer producer;
			producer.SetError();
			return producer.Consumer();
		}
		return HybridDecryptStream(
			std::move(consumer), mode,
			std::make_unique<DecryptBox<DecryptorT, PrivateKeyT>>(*keypair->PrivateKey()));
	}
}
