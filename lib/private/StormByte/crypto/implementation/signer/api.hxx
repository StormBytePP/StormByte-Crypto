/*
 * Copyright (C) 2024-2026 David C. Manuelda (StormBytePP)
 *
 * This file is part of StormByte.
 *
 * StormByte is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * StormByte is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with StormByte. If not, see <https://www.gnu.org/licenses/>.
 */

#pragma once

#include <StormByte/crypto/implementation/signer/details.hxx>
#include <StormByte/crypto/implementation/keypair/api.hxx>
#include <StormByte/crypto/keypair/generic.hxx>
#include <StormByte/crypto/password.hxx>
#include <StormByte/crypto/random.hxx>
#include <StormByte/crypto/typedefs.hxx>
#include <StormByte/crypto/visibility.h>

#include <filters.h>
#include <memory>
#include <span>
#include <string>

namespace StormByte::Crypto::Implementation::Signer {
	namespace {
		template<typename SignerT, typename PrivateKeyT>
		struct ConcreteSignBox final : SignBox {
			std::unique_ptr<PrivateKeyT> key;
			std::unique_ptr<SignerT> signer;
			Buffer::DataType signature;
			std::unique_ptr<CryptoPP::SignerFilter> filter;

			explicit ConcreteSignBox(const Password& privKey)
			{
				auto keyRes = KeyPair::DeserializeKey<PrivateKeyT>(privKey);
				if (!keyRes)
					return;
				key = std::make_unique<PrivateKeyT>(std::move(*keyRes));
				if (!key->Validate(RNG(), 3)) {
					key.reset();
					return;
				}
				signer = std::make_unique<SignerT>(*key);
				filter = std::make_unique<CryptoPP::SignerFilter>(
					RNG(), *signer,
					new CryptoPP::StringSinkTemplate<Buffer::DataType>(signature)
				);
			}

			bool Update(std::span<const std::byte> in) override
			{
				if (!filter)
					return false;
				try {
					filter->Put(
						reinterpret_cast<const CryptoPP::byte*>(in.data()),
						in.size_bytes());
					return true;
				} catch (...) {
					return false;
				}
			}

			bool Finalize(Buffer::DataType& out) override
			{
				if (!filter)
					return false;
				try {
					filter->MessageEnd();
					out = std::move(signature);
					filter.reset();
					return true;
				} catch (...) {
					return false;
				}
			}
		};

		template<typename VerifierT, typename PublicKeyT>
		struct ConcreteVerifyBox final : VerifyBox {
			std::unique_ptr<PublicKeyT> key;
			std::unique_ptr<VerifierT> verifier;
			bool result = false;
			std::unique_ptr<CryptoPP::SignatureVerificationFilter> filter;

			explicit ConcreteVerifyBox(const std::string& pubKey)
			{
				auto keyRes = KeyPair::DeserializeKey<PublicKeyT>(pubKey);
				if (!keyRes)
					return;
				key = std::make_unique<PublicKeyT>(std::move(*keyRes));
				if (!key->Validate(RNG(), 3)) {
					key.reset();
					return;
				}
				verifier = std::make_unique<VerifierT>(*key);
			}

			bool Begin(const std::string& signature) override
			{
				if (!verifier)
					return false;
				try {
					filter = std::make_unique<CryptoPP::SignatureVerificationFilter>(
						*verifier,
						new CryptoPP::ArraySink(
							reinterpret_cast<CryptoPP::byte*>(&result),
							sizeof(result)),
						CryptoPP::SignatureVerificationFilter::PUT_RESULT |
							CryptoPP::SignatureVerificationFilter::SIGNATURE_AT_BEGIN
					);
					filter->Put(
						reinterpret_cast<const CryptoPP::byte*>(signature.data()),
						signature.size());
					return true;
				} catch (...) {
					return false;
				}
			}

			bool Update(std::span<const std::byte> in) override
			{
				if (!filter)
					return false;
				try {
					filter->Put(
						reinterpret_cast<const CryptoPP::byte*>(in.data()),
						in.size_bytes());
					return true;
				} catch (...) {
					return false;
				}
			}

			bool Finalize() override
			{
				if (!filter)
					return false;
				try {
					filter->MessageEnd();
					filter.reset();
					return result;
				} catch (...) {
					return false;
				}
			}
		};
	}

	// ----- Sign -----

	template<typename SignerT, typename PrivateKeyT>
	bool Sign(std::span<const std::byte> data,
			const Password& privKey,
			Buffer::WriteOnly& output) noexcept
	{
		return SignSpan(
			data, output,
			std::make_unique<ConcreteSignBox<SignerT, PrivateKeyT>>(privKey));
	}

	template<typename SignerT, typename PrivateKeyT>
	bool Sign(std::span<const std::byte> data,
			const StormByte::Crypto::KeyPair::Generic::PointerType keypair,
			Buffer::WriteOnly& output) noexcept
	{
		if (!keypair || !keypair->HasPrivateKey())
			return false;
		return Sign<SignerT, PrivateKeyT>(data, *keypair->PrivateKey(), output);
	}

	template<typename SignerT, typename PrivateKeyT>
	Buffer::Consumer Sign(Buffer::Consumer consumer,
						Password privKey,
						ReadMode mode) noexcept
	{
		return SignStream(
			std::move(consumer), mode,
			std::make_unique<ConcreteSignBox<SignerT, PrivateKeyT>>(std::move(privKey)));
	}

	template<typename SignerT, typename PrivateKeyT>
	Buffer::Consumer Sign(Buffer::Consumer consumer,
						const StormByte::Crypto::KeyPair::Generic::PointerType keypair,
						ReadMode mode) noexcept
	{
		if (!keypair || !keypair->HasPrivateKey()) {
			Buffer::Producer producer;
			producer.SetError();
			return producer.Consumer();
		}
		return Sign<SignerT, PrivateKeyT>(
			std::move(consumer), *keypair->PrivateKey(), mode);
	}

	// ----- Verify -----

	template<typename VerifierT, typename PublicKeyT>
	bool Verify(std::span<const std::byte> data,
				const std::string& signature,
				const std::string& pubKey) noexcept
	{
		return VerifySpan(
			data, signature,
			std::make_unique<ConcreteVerifyBox<VerifierT, PublicKeyT>>(pubKey));
	}

	template<typename VerifierT, typename PublicKeyT>
	bool Verify(std::span<const std::byte> data,
				const std::string& signature,
				const StormByte::Crypto::KeyPair::Generic::PointerType keypair) noexcept
	{
		if (!keypair)
			return false;
		return Verify<VerifierT, PublicKeyT>(data, signature, keypair->PublicKey());
	}

	template<typename VerifierT, typename PublicKeyT>
	bool Verify(Buffer::Consumer consumer,
				const std::string& signature,
				const std::string& pubKey,
				ReadMode mode) noexcept
	{
		return VerifyStream(
			std::move(consumer), mode, signature,
			std::make_unique<ConcreteVerifyBox<VerifierT, PublicKeyT>>(pubKey));
	}

	template<typename VerifierT, typename PublicKeyT>
	bool Verify(Buffer::Consumer consumer,
				const std::string& signature,
				const StormByte::Crypto::KeyPair::Generic::PointerType keypair,
				ReadMode mode) noexcept
	{
		if (!keypair)
			return false;
		return Verify<VerifierT, PublicKeyT>(
			std::move(consumer), signature, keypair->PublicKey(), mode);
	}
}
