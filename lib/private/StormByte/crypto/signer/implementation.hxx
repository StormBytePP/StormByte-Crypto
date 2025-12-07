#pragma once

#include <StormByte/buffer/producer.hxx>
#include <StormByte/crypto/keypair/generic.hxx>
#include <StormByte/crypto/keypair/implementation.hxx>
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
	STORMBYTE_CRYPTO_PRIVATE bool Sign(std::span<const std::byte> dataSpan, const std::string& privKey, WriteOnly& output) noexcept {
		try {
			// Deserialize and validate the private key
			auto keyRes = KeyPair::DeserializeKey<PrivateKeyT>(privKey);
			if (!keyRes) {
				return false;
			}
			PrivateKeyT key = std::move(*keyRes);
			if (!key.Validate(RNG(), 3)) {
				return false;
			}

			// Initialize the signer
			SignerT signer(key);

			// Sign the message
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
		if (!keypair || !keypair->PrivateKey().has_value()) {
			return false;
		}
		return Sign<SignerT, PrivateKeyT>(dataSpan, keypair->PrivateKey().value(), output);
	}

	template<typename SignerT, typename PrivateKeyT>
	STORMBYTE_CRYPTO_PRIVATE Consumer Sign(Consumer consumer, const std::string& privKey, ReadMode mode) noexcept {
		Producer producer;

		std::thread([consumer, producer, privKey, mode]() mutable {
			try {
				// Deserialize and validate the private key
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

				// Initialize the signer
				SignerT signer(key);

				// Use a single SignerFilter to sign the whole stream incrementally.
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
						// unique_ptr will clean up filter
						producer.SetError();
						return;
					}

					// Feed data into the single SignerFilter
					filter->Put(reinterpret_cast<const CryptoPP::byte*>(data.data()), data.size());
				}

				// Finalize signature and emit result
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
		if (!keypair || !keypair->PrivateKey().has_value()) {
			producer.SetError();
			return producer.Consumer();
		}

		return Sign<SignerT, PrivateKeyT>(consumer, keypair->PrivateKey().value(), mode);
	}

	template<typename VerifierT, typename PublicKeyT>
	STORMBYTE_CRYPTO_PRIVATE bool Verify(std::span<const std::byte> data, const std::string& signature, const std::string& pubKey) noexcept {
		try {
			// Deserialize and validate the public key
			auto keyRes = KeyPair::DeserializeKey<PublicKeyT>(pubKey);
			if (!keyRes) {
				return false; // Public key deserialization failed
			}
			PublicKeyT key = std::move(*keyRes);
			if (!key.Validate(RNG(), 3)) {
				return false; // Public key validation failed
			}

			// Initialize the verifier
			VerifierT verifier(key);

			// Verify the signature
			bool result = false;
			CryptoPP::StringSource ss(
				signature + std::string(reinterpret_cast<const char*>(data.data()), data.size()),
				true,
				new CryptoPP::SignatureVerificationFilter(
					verifier,
					new CryptoPP::ArraySink((CryptoPP::byte*)&result, sizeof(result)),
					CryptoPP::SignatureVerificationFilter::PUT_RESULT | CryptoPP::SignatureVerificationFilter::SIGNATURE_AT_BEGIN
				)
			);

			return result;
		} catch (...) {
			return false; // Other errors
		}
	}

	template<typename VerifierT, typename PublicKeyT>
	STORMBYTE_CRYPTO_PRIVATE bool Verify(std::span<const std::byte> data, const std::string& signature, const KeyPair::Generic::PointerType keypair) noexcept {
		return Verify<VerifierT, PublicKeyT>(data, signature, keypair->PublicKey());
	}

	template<typename VerifierT, typename PublicKeyT>
	STORMBYTE_CRYPTO_PRIVATE bool Verify(Consumer consumer, const std::string& signature, const std::string& pubKey, ReadMode mode) noexcept {
		try {
			// Deserialize and validate the public key
			auto keyRes = KeyPair::DeserializeKey<PublicKeyT>(pubKey);
			if (!keyRes) {
				return false; // Public key deserialization failed
			}
			PublicKeyT key = std::move(*keyRes);
			if (!key.Validate(RNG(), 3)) {
				return false; // Public key validation failed
			}

			// Initialize the verifier
			VerifierT verifier(key);


			// Create a single SignatureVerificationFilter and feed signature then the streamed message
			bool verificationResult = false;
			auto vf = std::unique_ptr<CryptoPP::SignatureVerificationFilter>(
				new CryptoPP::SignatureVerificationFilter(
					verifier,
					new CryptoPP::ArraySink(reinterpret_cast<CryptoPP::byte*>(&verificationResult), sizeof(verificationResult)),
					CryptoPP::SignatureVerificationFilter::PUT_RESULT | CryptoPP::SignatureVerificationFilter::SIGNATURE_AT_BEGIN
				)
			);

			// Provide signature first
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

				if (!read_ok) {
					// unique_ptr will clean up vf
					return false;
				}

				vf->Put(reinterpret_cast<const CryptoPP::byte*>(data.data()), data.size());
			}

				vf->MessageEnd();

				return verificationResult;
		} catch (...) {
			return false; // Handle any unexpected errors
		}
	}

	template<typename VerifierT, typename PublicKeyT>
	STORMBYTE_CRYPTO_PRIVATE bool Verify(Consumer consumer, const std::string& signature, const KeyPair::Generic::PointerType keypair, ReadMode mode) noexcept {
		return Verify<VerifierT, PublicKeyT>(consumer, signature, keypair->PublicKey(), mode);
	}
}