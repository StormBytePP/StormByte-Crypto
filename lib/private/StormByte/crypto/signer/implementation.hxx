#pragma once

#include <StormByte/buffer/producer.hxx>
#include <StormByte/crypto/helpers/secure_wipe.hxx>
#include <StormByte/crypto/keypair/generic.hxx>
#include <StormByte/crypto/keypair/implementation.hxx>
#include <StormByte/crypto/password.hxx>
#include <StormByte/crypto/typedefs.hxx>

#include <thread>
#include <span>
#include <memory>

using StormByte::Buffer::DataType;
using StormByte::Buffer::Consumer;
using StormByte::Buffer::Producer;
using StormByte::Buffer::WriteOnly;

using namespace StormByte::Crypto;

namespace StormByte::Crypto::Signer {

	template<typename SignerT, typename PrivateKeyT>
	STORMBYTE_CRYPTO_PRIVATE bool Sign(std::span<const std::byte> dataSpan, const Password& privKey, WriteOnly& output) noexcept {
		try {
			auto keyRes = KeyPair::DeserializeKey<PrivateKeyT>(privKey);
			if (!keyRes)
				return false;
			PrivateKeyT key = std::move(*keyRes);
			if (!key.Validate(RNG(), 3))
				return false;

			SignerT signer(key);

			DataType signature;
			CryptoPP::StringSource(
				reinterpret_cast<const CryptoPP::byte*>(dataSpan.data()),
				dataSpan.size_bytes(),
				true,
				new CryptoPP::SignerFilter(
					RNG(),
					signer,
					new CryptoPP::StringSinkTemplate<DataType>(signature)
				)
			);

			return output.Write(std::move(signature));
		} catch (...) {
			return false;
		}
	}

	template<typename SignerT, typename PrivateKeyT>
	STORMBYTE_CRYPTO_PRIVATE bool Sign(std::span<const std::byte> dataSpan, const KeyPair::Generic::PointerType keypair, WriteOnly& output) noexcept {
		if (!keypair || !keypair->HasPrivateKey())
			return false;
		return Sign<SignerT, PrivateKeyT>(dataSpan, *keypair->PrivateKey(), output);
	}

	template<typename SignerT, typename PrivateKeyT>
	STORMBYTE_CRYPTO_PRIVATE Consumer Sign(Consumer consumer, Password privKey, ReadMode mode) noexcept {
		Producer producer;

		std::thread([consumer, producer, privKey = std::move(privKey), mode]() mutable {
			try {
				auto keyRes = KeyPair::DeserializeKey<PrivateKeyT>(privKey);
				if (!keyRes) {
					producer.SetError();
					return;
				}
				PrivateKeyT key = std::move(*keyRes);
				if (!key.Validate(RNG(), 3)) {
					producer.SetError();
					return;
				}

				SignerT signer(key);

				DataType signatureBin;
				auto filter = std::unique_ptr<CryptoPP::SignerFilter>(
					new CryptoPP::SignerFilter(
						RNG(),
						signer,
						new CryptoPP::StringSinkTemplate<DataType>(signatureBin)
					)
				);

				constexpr size_t chunkSize = 4096;
				while (!consumer.EoF()) {
					size_t availableBytes = consumer.AvailableBytes();
					if (availableBytes == 0) {
						std::this_thread::yield();
						continue;
					}

					size_t bytesToRead = std::min(availableBytes, chunkSize);
					DataType data;
					bool read_ok;
					if (mode == ReadMode::Copy)
						read_ok = consumer.Read(bytesToRead, data);
					else
						read_ok = consumer.Extract(bytesToRead, data);
					if (!read_ok) {
						producer.SetError();
						return;
					}

					filter->Put(reinterpret_cast<const CryptoPP::byte*>(data.data()), data.size());
				}

				filter->MessageEnd();

				if (!producer.Write(std::move(signatureBin))) {
					producer.SetError();
					return;
				}
				producer.Close();
			} catch (...) {
				producer.SetError();
			}
		}).detach();

		return producer.Consumer();
	}

	template<typename SignerT, typename PrivateKeyT>
	STORMBYTE_CRYPTO_PRIVATE Consumer Sign(Consumer consumer, const KeyPair::Generic::PointerType keypair, ReadMode mode) noexcept {
		Producer producer;
		if (!keypair || !keypair->HasPrivateKey()) {
			producer.SetError();
			return producer.Consumer();
		}

		return Sign<SignerT, PrivateKeyT>(consumer, *keypair->PrivateKey(), mode);
	}

	template<typename VerifierT, typename PublicKeyT>
	STORMBYTE_CRYPTO_PRIVATE bool Verify(std::span<const std::byte> data, const std::string& signature, const std::string& pubKey) noexcept {
		try {
			auto keyRes = KeyPair::DeserializeKey<PublicKeyT>(pubKey);
			if (!keyRes)
				return false;
			PublicKeyT key = std::move(*keyRes);
			if (!key.Validate(RNG(), 3))
				return false;

			VerifierT verifier(key);

			bool result = false;
			auto vf = std::unique_ptr<CryptoPP::SignatureVerificationFilter>(
				new CryptoPP::SignatureVerificationFilter(
					verifier,
					new CryptoPP::ArraySink(reinterpret_cast<CryptoPP::byte*>(&result), sizeof(result)),
					CryptoPP::SignatureVerificationFilter::PUT_RESULT | CryptoPP::SignatureVerificationFilter::SIGNATURE_AT_BEGIN
				)
			);

			vf->Put(reinterpret_cast<const CryptoPP::byte*>(signature.data()), signature.size());
			if (!data.empty())
				vf->Put(reinterpret_cast<const CryptoPP::byte*>(data.data()), data.size());
			vf->MessageEnd();

			return result;
		} catch (...) {
			return false;
		}
	}

	template<typename VerifierT, typename PublicKeyT>
	STORMBYTE_CRYPTO_PRIVATE bool Verify(std::span<const std::byte> data, const std::string& signature, const KeyPair::Generic::PointerType keypair) noexcept {
		if (!keypair)
			return false;
		return Verify<VerifierT, PublicKeyT>(data, signature, keypair->PublicKey());
	}

	template<typename VerifierT, typename PublicKeyT>
	STORMBYTE_CRYPTO_PRIVATE bool Verify(Consumer consumer, const std::string& signature, const std::string& pubKey, ReadMode mode) noexcept {
		try {
			auto keyRes = KeyPair::DeserializeKey<PublicKeyT>(pubKey);
			if (!keyRes)
				return false;
			PublicKeyT key = std::move(*keyRes);
			if (!key.Validate(RNG(), 3))
				return false;

			VerifierT verifier(key);

			bool verificationResult = false;
			auto vf = std::unique_ptr<CryptoPP::SignatureVerificationFilter>(
				new CryptoPP::SignatureVerificationFilter(
					verifier,
					new CryptoPP::ArraySink(reinterpret_cast<CryptoPP::byte*>(&verificationResult), sizeof(verificationResult)),
					CryptoPP::SignatureVerificationFilter::PUT_RESULT | CryptoPP::SignatureVerificationFilter::SIGNATURE_AT_BEGIN
				)
			);

			vf->Put(reinterpret_cast<const CryptoPP::byte*>(signature.data()), signature.size());

			constexpr size_t chunkSize = 4096;
			while (!consumer.EoF()) {
				size_t availableBytes = consumer.AvailableBytes();
				if (availableBytes == 0) {
					std::this_thread::yield();
					continue;
				}

				size_t bytesToRead = std::min(availableBytes, chunkSize);
				DataType data;
				bool read_ok;
				if (mode == ReadMode::Copy)
					read_ok = consumer.Read(bytesToRead, data);
				else
					read_ok = consumer.Extract(bytesToRead, data);

				if (!read_ok)
					return false;

				vf->Put(reinterpret_cast<const CryptoPP::byte*>(data.data()), data.size());
			}

			vf->MessageEnd();

			return verificationResult;
		} catch (...) {
			return false;
		}
	}

	template<typename VerifierT, typename PublicKeyT>
	STORMBYTE_CRYPTO_PRIVATE bool Verify(Consumer consumer, const std::string& signature, const KeyPair::Generic::PointerType keypair, ReadMode mode) noexcept {
		if (!keypair)
			return false;
		return Verify<VerifierT, PublicKeyT>(consumer, signature, keypair->PublicKey(), mode);
	}
}
