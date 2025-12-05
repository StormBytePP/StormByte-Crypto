#include <StormByte/crypto/implementation/encryption/dsa.hxx>

#include <algorithm>
#include <cryptlib.h>
#include <base64.h>
#include <dsa.h>
#include <hex.h>
#include <osrng.h>
#include <filters.h>
#include <string>
#include <thread>

using namespace StormByte::Crypto::Implementation::Encryption;

namespace {
	std::string SerializeKey(const CryptoPP::DSA::PrivateKey& key) {
		std::string keyString;
		CryptoPP::ByteQueue queue;
		key.Save(queue); // Save key in ASN.1 format
		CryptoPP::Base64Encoder encoder(new CryptoPP::StringSink(keyString), false); // Base64 encode
		queue.CopyTo(encoder);
		encoder.MessageEnd();
		return keyString;
	}

	std::string SerializeKey(const CryptoPP::DSA::PublicKey& key) {
		std::string keyString;
		CryptoPP::ByteQueue queue;
		key.Save(queue); // Save key in ASN.1 format
		CryptoPP::Base64Encoder encoder(new CryptoPP::StringSink(keyString), false); // Base64 encode
		queue.CopyTo(encoder);
		encoder.MessageEnd();
		return keyString;
	}

	CryptoPP::DSA::PublicKey DeserializePublicKey(const std::string& keyString) {
		CryptoPP::DSA::PublicKey key;
		CryptoPP::Base64Decoder decoder;
		CryptoPP::StringSource keyStringSource(keyString, true, new CryptoPP::Redirector(decoder));
		key.Load(decoder); // Load the decoded key
		return key;
	}

	CryptoPP::DSA::PrivateKey DeserializePrivateKey(const std::string& keyString) {
		CryptoPP::DSA::PrivateKey key;
		CryptoPP::Base64Decoder decoder;
		CryptoPP::StringSource keyStringSource(keyString, true, new CryptoPP::Redirector(decoder));
		key.Load(decoder); // Load the decoded key
		return key;
	}
}

// Key Pair Generation
ExpectedKeyPair DSA::GenerateKeyPair(const int& keyStrength) noexcept {
	try {
		CryptoPP::AutoSeededRandomPool rng;

		// Generate DSA domain parameters
		CryptoPP::DL_GroupParameters_DSA params;
		params.GenerateRandomWithKeySize(rng, keyStrength);
		
		// Extract domain parameters
		const CryptoPP::Integer& p = params.GetModulus();
		const CryptoPP::Integer& q = params.GetSubgroupOrder();
		const CryptoPP::Integer& g = params.GetSubgroupGenerator();
		
		// Generate random private exponent
		CryptoPP::Integer x(rng, CryptoPP::Integer::One(), q - CryptoPP::Integer::One());
		
		// Initialize private key with domain parameters and exponent
		// Note: We avoid using Initialize(params, x) or GenerateRandomWithKeySize
		// because they use NameValuePairs internally, which has a bug in Crypto++ 8.9.0
		// when built with clang/libc++ that causes RTTI pointer type mismatches.
		CryptoPP::DSA::PrivateKey privateKey;
		privateKey.AccessGroupParameters().Initialize(p, q, g);
		privateKey.SetPrivateExponent(x);

		// Generate the public key
		// Note: We use MakePublicKey instead of AssignFrom to avoid the same
		// NameValuePairs bug in Crypto++ 8.9.0 + clang/libc++
		CryptoPP::DSA::PublicKey publicKey;
		privateKey.MakePublicKey(publicKey);

		// Validate the keys
		if (!privateKey.Validate(rng, 3)) {
			return StormByte::Unexpected<Exception>("Private key validation failed");
		}
		if (!publicKey.Validate(rng, 3)) {
			return StormByte::Unexpected<Exception>("Public key validation failed");
		}

		// Serialize the keys
		return KeyPair{
			.Private = SerializeKey(privateKey),
			.Public = SerializeKey(publicKey),
		};
	} catch (const std::exception& e) {
		return StormByte::Unexpected<Exception>("Unexpected error during key generation: " + std::string(e.what()));
	}
}

// Signing with std::string
ExpectedCryptoString DSA::Sign(const std::string& message, const std::string& privateKey) noexcept {
	try {
		CryptoPP::AutoSeededRandomPool rng;

		// Deserialize and validate the private key
		CryptoPP::DSA::PrivateKey key = DeserializePrivateKey(privateKey);
		if (!key.Validate(rng, 3)) {
			return StormByte::Unexpected<Exception>("Private key validation failed");
		}

		// Initialize the signer
		CryptoPP::DSA::Signer signer(key);

		// Sign the message
		std::string signature;
		CryptoPP::StringSource ss(
			message, true,
			new CryptoPP::SignerFilter(
				rng, signer,
				new CryptoPP::StringSink(signature)
			)
		);

		return signature;
	} catch (const std::exception& e) {
		return StormByte::Unexpected<Exception>("DSA signing failed: " + std::string(e.what()));
	}
}

// Signing with Buffer::FIFO
ExpectedCryptoBuffer DSA::Sign(const Buffer::FIFO& message, const std::string& privateKey) noexcept {
	try {
		CryptoPP::AutoSeededRandomPool rng;

		// Deserialize and validate the private key
		CryptoPP::DSA::PrivateKey key = DeserializePrivateKey(privateKey);
		if (!key.Validate(rng, 3)) {
			return StormByte::Unexpected<Exception>("Private key validation failed");
		}

		// Initialize the signer
		CryptoPP::DSA::Signer signer(key);

		// Sign the message
		auto data = const_cast<StormByte::Buffer::FIFO&>(message).Extract(0);
		if (!data.has_value()) {
			return StormByte::Unexpected<Exception>("Failed to extract data from message buffer");
		}
		std::string signature;
		CryptoPP::StringSource ss(
			reinterpret_cast<const CryptoPP::byte*>(data.value().data()), data.value().size(), true,
			new CryptoPP::SignerFilter(rng, signer, new CryptoPP::StringSink(signature))
		);

		// Convert the signature to a buffer
		std::vector<std::byte> signatureBuffer(signature.size());
		std::transform(signature.begin(), signature.end(), signatureBuffer.begin(),
					[](char c) { return static_cast<std::byte>(c); });

		StormByte::Buffer::FIFO buffer;
		(void)buffer.Write(signatureBuffer);
		return buffer;
	} catch (const std::exception& e) {
		return StormByte::Unexpected<Exception>("DSA signing failed: " + std::string(e.what()));
	}
}

// Signing with Buffer::Consumer
StormByte::Buffer::Consumer DSA::Sign(Buffer::Consumer consumer, const std::string& privateKey) noexcept {
	auto producer = std::make_shared<StormByte::Buffer::Producer>();

	std::thread([consumer, producer, privateKey]() mutable {
		try {
			CryptoPP::AutoSeededRandomPool rng;

			// Deserialize and validate the private key
			CryptoPP::DSA::PrivateKey key = DeserializePrivateKey(privateKey);
			if (!key.Validate(rng, 3)) {
				producer->Close();
				return;
			}

			// Initialize the signer
			CryptoPP::DSA::Signer signer(key);

			constexpr size_t chunkSize = 4096;
			std::string signatureChunk;
			// Batch writes to reduce internal reallocations
			std::vector<std::byte> batchBuffer;
			batchBuffer.reserve(chunkSize * 2); // Pre-allocate for batching

			while (!consumer.EoF()) {
				const size_t availableBytes = consumer.AvailableBytes();
				if (availableBytes == 0) {
					// No bytes available yet; wait briefly and retry.
					std::this_thread::sleep_for(std::chrono::milliseconds(10));
					continue;
				}

				size_t bytesToRead = std::min(availableBytes, chunkSize);
				// Use Span for zero-copy read
				auto spanResult = consumer.Extract(bytesToRead);
				if (!spanResult.has_value()) {
					producer->Close();
					return;
				}

				const auto& inputSpan = spanResult.value();
				signatureChunk.clear();

				// Sign the chunk
				CryptoPP::StringSource ss(
					reinterpret_cast<const CryptoPP::byte*>(inputSpan.data()), inputSpan.size(), true,
					new CryptoPP::SignerFilter(
						rng, signer,
						new CryptoPP::StringSink(signatureChunk)
					)
				);

				// Accumulate into batch buffer
				for (size_t i = 0; i < signatureChunk.size(); ++i) {
					batchBuffer.push_back(static_cast<std::byte>(signatureChunk[i]));
				}

				// Write in larger batches to reduce reallocation overhead
				if (batchBuffer.size() >= chunkSize) {
					(void)producer->Write(std::move(batchBuffer));
					batchBuffer.clear();
					batchBuffer.reserve(chunkSize * 2);
					// Clean consumed data periodically (only when batch is written)
					consumer.Clean();
				}
			}
			// Write any remaining data
			if (!batchBuffer.empty()) {
				(void)producer->Write(std::move(batchBuffer));
			}
			producer->Close(); // Mark processing complete // Update status (EOF or Error)
		} catch (...) {
			producer->Close();
		}
	}).detach();

	return producer->Consumer();
}

// Verification with std::string
bool DSA::Verify(const std::string& message, const std::string& signature, const std::string& publicKey) noexcept {
	try {
		CryptoPP::AutoSeededRandomPool rng;

		// Deserialize and validate the public key
		CryptoPP::DSA::PublicKey key = DeserializePublicKey(publicKey);
		if (!key.Validate(rng, 3)) {
			return false; // Public key validation failed
		}

		// Initialize the verifier
		CryptoPP::DSA::Verifier verifier(key);

		// Verify the signature
		bool result = false;
		CryptoPP::StringSource ss(
			signature + message, true,
			new CryptoPP::SignatureVerificationFilter(
				verifier,
				new CryptoPP::ArraySink((CryptoPP::byte*)&result, sizeof(result)),
				CryptoPP::SignatureVerificationFilter::PUT_RESULT | CryptoPP::SignatureVerificationFilter::SIGNATURE_AT_BEGIN
			)
		);

		return result;
	} catch (const CryptoPP::Exception&) {
		return false; // Signature verification failed
	} catch (const std::exception&) {
		return false; // Other errors
	}
}

// Verification with Buffer::FIFO
bool DSA::Verify(const Buffer::FIFO& message, const std::string& signature, const std::string& publicKey) noexcept {
	try {
		CryptoPP::AutoSeededRandomPool rng;

		// Deserialize and validate the public key
		CryptoPP::DSA::PublicKey key = DeserializePublicKey(publicKey);
		if (!key.Validate(rng, 3)) {
			return false; // Public key validation failed
		}

		// Initialize the verifier
		CryptoPP::DSA::Verifier verifier(key);

		// Verify the signature
		auto data = const_cast<StormByte::Buffer::FIFO&>(message).Extract(0);
		if (!data.has_value()) {
			return false;
		}
		bool result = false;
		CryptoPP::StringSource ss(
			signature + std::string(reinterpret_cast<const char*>(data.value().data()), data.value().size()), true,
			new CryptoPP::SignatureVerificationFilter(
				verifier,
				new CryptoPP::ArraySink((CryptoPP::byte*)&result, sizeof(result)),
				CryptoPP::SignatureVerificationFilter::PUT_RESULT | CryptoPP::SignatureVerificationFilter::SIGNATURE_AT_BEGIN
			)
		);

		return result;
	} catch (const CryptoPP::Exception&) {
		return false; // Signature verification failed
	} catch (const std::exception&) {
		return false; // Other errors
	}
}

// Verification with Buffer::Consumer
bool DSA::Verify(Buffer::Consumer consumer, const std::string& signature, const std::string& publicKey) noexcept {
	try {
		CryptoPP::AutoSeededRandomPool rng;

		// Deserialize and validate the public key
		CryptoPP::DSA::PublicKey key = DeserializePublicKey(publicKey);
		if (!key.Validate(rng, 3)) {
			return false; // Public key validation failed
		}

		// Initialize the verifier
		CryptoPP::DSA::Verifier verifier(key);

		constexpr size_t chunkSize = 4096;
		bool verificationResult = false;

		while (!consumer.EoF()) {
			const size_t availableBytes = consumer.AvailableBytes();
			if (availableBytes == 0) {
				std::this_thread::sleep_for(std::chrono::milliseconds(10));
				continue;
			}

			size_t bytesToRead = std::min(availableBytes, chunkSize);
			// Use Span for zero-copy read
			auto spanResult = consumer.Extract(bytesToRead);
			if (!spanResult.has_value()) {
				return false; // Error reading data
			}

			const auto& inputSpan = spanResult.value();

			// Verify the chunk
			CryptoPP::StringSource ss(
				signature + std::string(reinterpret_cast<const char*>(inputSpan.data()), inputSpan.size()), true,
				new CryptoPP::SignatureVerificationFilter(
					verifier,
					new CryptoPP::ArraySink(reinterpret_cast<CryptoPP::byte*>(&verificationResult), sizeof(verificationResult)),
					CryptoPP::SignatureVerificationFilter::PUT_RESULT | CryptoPP::SignatureVerificationFilter::SIGNATURE_AT_BEGIN
				)
			);

			if (!verificationResult) {
				return false; // Verification failed
			}
		}

		return verificationResult; // Verification succeeded
	} catch (...) {
		return false; // Handle any unexpected errors
	}
}