#include <StormByte/crypto/random.hxx>
#include <StormByte/crypto/implementation/encryption/ecdsa.hxx>

#include <algorithm>
#include <cryptlib.h>
#include <base64.h>
#include <eccrypto.h>
#include <oids.h>
#include <filters.h>
#include <string>
#include <thread>

using StormByte::Buffer::DataType;
using StormByte::Buffer::FIFO;
using StormByte::Buffer::Consumer;
using StormByte::Buffer::Producer;
using namespace StormByte::Crypto;
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
		// Select the curve
		CryptoPP::OID curve;
		if (curveName == "secp256r1") {
			curve = CryptoPP::ASN1::secp256r1();
		} else if (curveName == "secp384r1") {
			curve = CryptoPP::ASN1::secp384r1();
		} else if (curveName == "secp521r1") {
			curve = CryptoPP::ASN1::secp521r1();
		} else {
			return Unexpected(KeyPairException("Unknown curve name: {}", curveName));
		}

		// Generate the private key
		CryptoECDSA::PrivateKey privateKey;
		privateKey.Initialize(RNG(), curve);

		// Generate the public key
		CryptoECDSA::PublicKey publicKey;
		privateKey.MakePublicKey(publicKey);

		// Validate the keys
		if (!privateKey.Validate(RNG(), 3)) {
			return Unexpected(KeyPairException("Private key validation failed"));
		}
		if (!publicKey.Validate(RNG(), 3)) {
			return Unexpected(KeyPairException("Public key validation failed"));
		}

		// Serialize the keys
		return KeyPair{
			.Private = SerializeKey(privateKey),
			.Public = SerializeKey(publicKey),
		};
	} catch (const std::exception& e) {
		return Unexpected(KeyPairException("Unexpected error during key generation: {}", e.what()));
	}
}

// Signing
ExpectedCryptoString ECDSA::Sign(const std::string& message, const std::string& privateKey) noexcept {
	try {
		// Deserialize and validate the private key
		CryptoECDSA::PrivateKey key = DeserializePrivateKey(privateKey);
		if (!key.Validate(RNG(), 3)) {
			return Unexpected(SignerException("Private key validation failed"));
		}

		// Initialize the signer
		CryptoECDSA::Signer signer(key);

		// Sign the message
		std::string signature;
		CryptoPP::StringSource ss(
			message, true,
			new CryptoPP::SignerFilter(
				RNG(),
				signer,
				new CryptoPP::StringSink(signature)
			)
		);

		return signature;
	} catch (const std::exception& e) {
		return Unexpected(SignerException("ECDSA signing failed: {}", e.what()));
	}
}

ExpectedCryptoBuffer ECDSA::Sign(const FIFO& message, const std::string& privateKey) noexcept {
	try {
		// Deserialize and validate the private key
		CryptoECDSA::PrivateKey key = DeserializePrivateKey(privateKey);
		if (!key.Validate(RNG(), 3)) {
			return Unexpected(SignerException("Private key validation failed"));
		}

		// Initialize the signer
		CryptoECDSA::Signer signer(key);

		// Sign the message
		DataType data;
		auto read_ok = message.Read(data);
		if (!read_ok.has_value()) {
			return Unexpected(SignerException("Failed to extract data from message buffer"));
		}
		std::string signature;
		CryptoPP::StringSource ss(
			reinterpret_cast<const CryptoPP::byte*>(data.data()),
			data.size(),
			true,
			new CryptoPP::SignerFilter(
				RNG(),
				signer,
				new CryptoPP::StringSink(signature)
			)
		);

		FIFO buffer;
		(void)buffer.Write(std::move(signature));
		return buffer;
	} catch (const std::exception& e) {
		return Unexpected(SignerException("ECDSA signing failed: {}", e.what()));
	}
}

// Signing with Consumer
Consumer ECDSA::Sign(Consumer consumer, const std::string& privateKey) noexcept {
	Producer producer;

	std::thread([consumer, producer, privateKey]() mutable {
		try {
			// Deserialize and validate the private key
			CryptoECDSA::PrivateKey key = DeserializePrivateKey(privateKey);
			if (!key.Validate(RNG(), 3)) {
				producer.SetError();
				return;
			}

			// Initialize the signer
			CryptoECDSA::Signer signer(key);

			constexpr size_t chunkSize = 4096;
		
			while (!consumer.EoF()) {
				size_t availableBytes = consumer.AvailableBytes();
				if (availableBytes == 0) {
					std::this_thread::yield();
					continue;
				}

				std::string signatureChunk;
				size_t bytesToRead = std::min(availableBytes, chunkSize);
				DataType data;
				auto spanResult = consumer.Extract(bytesToRead, data);
				if (!spanResult.has_value()) {
					producer.SetError();
					return;
				}

				// Sign the chunk
				CryptoPP::StringSource ss(
					reinterpret_cast<const CryptoPP::byte*>(data.data()),
					data.size(),
					true,
					new CryptoPP::SignerFilter(
						RNG(),
						signer,
						new CryptoPP::StringSink(signatureChunk)
					)
				);

				(void)producer.Write(std::move(signatureChunk));
			}
			producer.Close(); // Mark processing complete // Update status (EOF or Error)
		} catch (...) {
			producer.SetError();
		}
	}).detach();

	return producer.Consumer();
}

// Verification
bool ECDSA::Verify(const std::string& message, const std::string& signature, const std::string& publicKey) noexcept {
	try {
		// Deserialize and validate the public key
		CryptoECDSA::PublicKey key = DeserializePublicKey(publicKey);
		if (!key.Validate(RNG(), 3)) {
			return false; // Public key validation failed
		}

		// Initialize the verifier
		CryptoECDSA::Verifier verifier(key);

		// Verify the signature
		bool result = false;
		CryptoPP::StringSource ss(
			signature + message,
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

// Verification with FIFO
bool ECDSA::Verify(const FIFO& message, const std::string& signature, const std::string& publicKey) noexcept {
	try {
		// Deserialize and validate the public key
		CryptoECDSA::PublicKey key = DeserializePublicKey(publicKey);
		if (!key.Validate(RNG(), 3)) {
			return false; // Public key validation failed
		}

		// Initialize the verifier
		CryptoECDSA::Verifier verifier(key);

		// Verify the signature
		DataType data;
		auto read_ok = message.Read(data);
		if (!read_ok.has_value()) {
			return false;
		}
		bool result = false;
		CryptoPP::StringSource ss(
			signature + std::string(reinterpret_cast<const char*>(data.data()), data.size())
			,
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

// Verification with Consumer
bool ECDSA::Verify(Consumer consumer, const std::string& signature, const std::string& publicKey) noexcept {
	try {
		// Deserialize and validate the public key
		CryptoECDSA::PublicKey key = DeserializePublicKey(publicKey);
		if (!key.Validate(RNG(), 3)) {
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
			DataType data;
			auto spanResult = consumer.Extract(bytesToRead, data);
			if (!spanResult.has_value()) {
				return false; // Error reading data
			}

			// Verify the chunk
			CryptoPP::StringSource ss(
				signature + std::string(reinterpret_cast<const char*>(data.data()), data.size()),
				true,
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