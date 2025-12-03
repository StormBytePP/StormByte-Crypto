#include <StormByte/crypto/implementation/encryption/ecdsa.hxx>

#include <algorithm>
#include <cryptlib.h>
#include <base64.h>
#include <eccrypto.h>
#include <osrng.h>
#include <oids.h>
#include <filters.h>
#include <string>
#include <thread>

using namespace StormByte::Crypto::Implementation::Encryption;

namespace {
	using CryptoECDSA = CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>;

	std::string SerializeKey(const CryptoECDSA::PrivateKey& key) {
		std::string keyString;
		CryptoPP::ByteQueue queue;
		key.Save(queue); // Save key in ASN.1 format
		CryptoPP::Base64Encoder encoder(new CryptoPP::StringSink(keyString), false); // Base64 encode
		queue.CopyTo(encoder);
		encoder.MessageEnd();
		return keyString;
	}

	std::string SerializeKey(const CryptoECDSA::PublicKey& key) {
		std::string keyString;
		CryptoPP::ByteQueue queue;
		key.Save(queue); // Save key in ASN.1 format
		CryptoPP::Base64Encoder encoder(new CryptoPP::StringSink(keyString), false); // Base64 encode
		queue.CopyTo(encoder);
		encoder.MessageEnd();
		return keyString;
	}

	CryptoECDSA::PublicKey DeserializePublicKey(const std::string& keyString) {
		CryptoECDSA::PublicKey key;
		CryptoPP::Base64Decoder decoder;
		CryptoPP::StringSource keySource(keyString, true, new CryptoPP::Redirector(decoder));
		key.Load(decoder);
		return key;
	}

	CryptoECDSA::PrivateKey DeserializePrivateKey(const std::string& keyString) {
		CryptoECDSA::PrivateKey key;
		CryptoPP::Base64Decoder decoder;
		CryptoPP::StringSource keySource(keyString, true, new CryptoPP::Redirector(decoder));
		key.Load(decoder);
		return key;
	}
}

// Key Pair Generation
ExpectedKeyPair ECDSA::GenerateKeyPair(const std::string& curveName) noexcept {
	try {
		CryptoPP::AutoSeededRandomPool rng;

		// Select the curve
		CryptoPP::OID curve;
		if (curveName == "secp256r1") {
			curve = CryptoPP::ASN1::secp256r1();
		} else if (curveName == "secp384r1") {
			curve = CryptoPP::ASN1::secp384r1();
		} else if (curveName == "secp521r1") {
			curve = CryptoPP::ASN1::secp521r1();
		} else {
			return StormByte::Unexpected<Exception>("Unknown curve name: " + curveName);
		}

		// Generate the private key
		CryptoECDSA::PrivateKey privateKey;
		privateKey.Initialize(rng, curve);

		// Generate the public key
		CryptoECDSA::PublicKey publicKey;
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

// Signing
ExpectedCryptoString ECDSA::Sign(const std::string& message, const std::string& privateKey) noexcept {
	try {
		CryptoPP::AutoSeededRandomPool rng;

		// Deserialize and validate the private key
		CryptoECDSA::PrivateKey key = DeserializePrivateKey(privateKey);
		if (!key.Validate(rng, 3)) {
			return StormByte::Unexpected<Exception>("Private key validation failed");
		}

		// Initialize the signer
		CryptoECDSA::Signer signer(key);

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
		return StormByte::Unexpected<Exception>("ECDSA signing failed: " + std::string(e.what()));
	}
}

ExpectedCryptoBuffer ECDSA::Sign(const Buffer::FIFO& message, const std::string& privateKey) noexcept {
	try {
		CryptoPP::AutoSeededRandomPool rng;

		// Deserialize and validate the private key
		CryptoECDSA::PrivateKey key = DeserializePrivateKey(privateKey);
		if (!key.Validate(rng, 3)) {
			return StormByte::Unexpected<Exception>("Private key validation failed");
		}

	// Initialize the signer
	CryptoECDSA::Signer signer(key);

	// Sign the message
	auto data = const_cast<StormByte::Buffer::FIFO&>(message).Extract(0);
	if (!data.has_value()) {
		return StormByte::Unexpected<Exception>("Failed to extract data from message buffer");
	}
	std::string signature;
	CryptoPP::StringSource ss(
		reinterpret_cast<const CryptoPP::byte*>(data.value().data()), data.value().size(), true,
		new CryptoPP::SignerFilter(rng, signer, new CryptoPP::StringSink(signature))
	);		// Convert the signature to a buffer
		std::vector<std::byte> signatureBuffer(signature.size());
		std::transform(signature.begin(), signature.end(), signatureBuffer.begin(),
					[](char c) { return static_cast<std::byte>(c); });

		StormByte::Buffer::FIFO buffer;
		(void)buffer.Write(signatureBuffer);
		return buffer;
	} catch (const std::exception& e) {
		return StormByte::Unexpected<Exception>("ECDSA signing failed: " + std::string(e.what()));
	}
}

// Signing with Buffer::Consumer
StormByte::Buffer::Consumer ECDSA::Sign(Buffer::Consumer consumer, const std::string& privateKey) noexcept {
	auto producer = std::make_shared<StormByte::Buffer::Producer>();

	std::thread([consumer, producer, privateKey]() mutable {
		try {
			CryptoPP::AutoSeededRandomPool rng;

			size_t chunksProcessed = 0;

			// Deserialize and validate the private key
			CryptoECDSA::PrivateKey key = DeserializePrivateKey(privateKey);
			if (!key.Validate(rng, 3)) {
				producer->Close();
				return;
			}

			// Initialize the signer
			CryptoECDSA::Signer signer(key);

			constexpr size_t chunkSize = 4096;
			std::string signatureChunk;

			while (!consumer.EoF()) {
				size_t availableBytes = consumer.AvailableBytes();
				if (availableBytes == 0) {
					std::this_thread::yield();
					continue;
				}

				size_t bytesToRead = std::min(availableBytes, chunkSize);
				// Use Span for zero-copy read
			auto spanResult = consumer.Span(bytesToRead);
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

								std::vector<std::byte> byteData;
				byteData.reserve(signatureChunk.size());
				for (size_t i = 0; i < signatureChunk.size(); ++i) {
					byteData.push_back(static_cast<std::byte>(signatureChunk[i]));
				}
				(void)producer->Write(byteData);
				// Clean periodically (every 16 chunks to balance memory vs performance)
				if (++chunksProcessed % 16 == 0) {
					consumer.Clean();
				}
			}
			producer->Close(); // Mark processing complete // Update status (EOF or Error)
		} catch (...) {
			producer->Close();
		}
	}).detach();

	return producer->Consumer();
}

// Verification
bool ECDSA::Verify(const std::string& message, const std::string& signature, const std::string& publicKey) noexcept {
	try {
		CryptoPP::AutoSeededRandomPool rng;

		// Deserialize and validate the public key
		CryptoECDSA::PublicKey key = DeserializePublicKey(publicKey);
		if (!key.Validate(rng, 3)) {
			return false; // Public key validation failed
		}

		// Initialize the verifier
		CryptoECDSA::Verifier verifier(key);

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
bool ECDSA::Verify(const Buffer::FIFO& message, const std::string& signature, const std::string& publicKey) noexcept {
	try {
		CryptoPP::AutoSeededRandomPool rng;

		// Deserialize and validate the public key
		CryptoECDSA::PublicKey key = DeserializePublicKey(publicKey);
		if (!key.Validate(rng, 3)) {
			return false; // Public key validation failed
		}

	// Initialize the verifier
	CryptoECDSA::Verifier verifier(key);

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
	);		return result;
	} catch (const CryptoPP::Exception&) {
		return false; // Signature verification failed
	} catch (const std::exception&) {
		return false; // Other errors
	}
}

// Verification with Buffer::Consumer
bool ECDSA::Verify(Buffer::Consumer consumer, const std::string& signature, const std::string& publicKey) noexcept {
	try {
		CryptoPP::AutoSeededRandomPool rng;

		// Deserialize and validate the public key
		CryptoECDSA::PublicKey key = DeserializePublicKey(publicKey);
		if (!key.Validate(rng, 3)) {
			return false; // Public key validation failed
		}

		// Initialize the verifier
		CryptoECDSA::Verifier verifier(key);

		constexpr size_t chunkSize = 4096;
		bool verificationResult = false;

		while (!consumer.EoF()) {
			size_t availableBytes = consumer.AvailableBytes();
			if (availableBytes == 0) {
				std::this_thread::yield();
				continue;
			}

			size_t bytesToRead = std::min(availableBytes, chunkSize);
			// Use Span for zero-copy read
			auto spanResult = consumer.Span(bytesToRead);
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